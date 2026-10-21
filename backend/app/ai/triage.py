"""Orchestrates AI analysis of an incident: build a compact prompt from
detection summaries only (never raw log fields), call the configured
provider, validate + verify its output, and fall back to a deterministic
template on any failure. Recommended actions always come from the
technique-to-mitigation playbook, never from the model, so the AI never
decides on its own what to recommend - it only explains."""

import json
import re
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.ai.client import AIProviderError, LLMClient, get_client
from app.ai.prompts import build_prompt
from app.ai.verify import AIFinding, AIModelOutput, merge_findings_by_technique, verify_findings
from app.audit import log_action
from app.config import settings
from app.detection.attack_map import MITIGATIONS, TECHNIQUE_NAMES
from app.models import Action, AIAnalysis, AuditLog, Detection

MAX_ATTEMPTS = 2  # one try + one retry, then fall back to the template

_SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|bearer|authorization)\S*[:=]\s*\S+")
_DIGIT_PATTERN = re.compile(r"\d")
_SENTENCE_SPLIT_PATTERN = re.compile(r"[.!?]+")
MAX_NARRATIVE_SENTENCES = 5

# benign < suspicious < malicious. The model only explains; the verdict floor
# below is the actual, code-computed decision of "how bad is this at minimum".
_VERDICT_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}


def _max_risk_score(detections: list[Detection]) -> float:
    return max((d.risk_score for d in detections), default=0.0)


def _verdict_floor(max_risk: float) -> str:
    """The verdict can never be softer than what the rule engine's own risk
    score implies: High/Critical risk (score >= 60) must read as malicious,
    Medium (>= 30) at least suspicious. The AI explains, it never overrides."""
    if max_risk >= 60:
        return "malicious"
    if max_risk >= 30:
        return "suspicious"
    return "benign"


def _apply_verdict_floor(verdict: str, floor: str) -> str:
    return floor if _VERDICT_RANK[floor] > _VERDICT_RANK[verdict] else verdict


def _has_disallowed_numbers(result: AIModelOutput) -> bool:
    """All numeric facts (scores, counts, confidences) are computed in code and
    shown in the UI separately. If the model's prose contains any digit, it has
    either invented a number or restated one it could get wrong - either way,
    reject it rather than risk showing the analyst a fabricated figure."""
    texts = [result.reasoning, result.narrative, result.risk_explanation] + [f.claim for f in result.findings]
    return any(_DIGIT_PATTERN.search(text) for text in texts)


def _narrative_too_long(result: AIModelOutput) -> bool:
    sentences = [s for s in _SENTENCE_SPLIT_PATTERN.split(result.narrative) if s.strip()]
    return len(sentences) > MAX_NARRATIVE_SENTENCES


def _redact(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    return _SECRET_PATTERN.sub(r"\1=[REDACTED]", text)[:limit]


def _build_summary(detections: list[Detection]):
    """Compact, LLM-facing summary: detection-level fields only (rule name, ATT&CK
    ids, scores, event ids). Never includes raw event fields like command_line,
    message, or user, which is where untrusted/log-controlled text would live."""
    summary = []
    known_event_ids: set[str] = set()
    technique_ids: set[str] = set()
    event_to_techniques: dict[str, set[str]] = {}
    for d in detections:
        tids = json.loads(d.technique_ids)
        eids = json.loads(d.matched_event_ids)
        technique_ids.update(tids)
        for eid in eids:
            known_event_ids.add(eid)
            event_to_techniques.setdefault(eid, set()).update(tids)
        summary.append(
            {
                "detection_id": d.id,
                "rule_name": d.rule_name,
                "technique_ids": tids,
                "tactics": json.loads(d.tactics),
                "severity": d.severity,
                "confidence": d.confidence,
                "risk_score": d.risk_score,
                "risk_level": d.risk_level,
                "event_count": d.event_count,
                "event_ids": eids,
                "first_seen": d.first_seen.isoformat(),
                "last_seen": d.last_seen.isoformat(),
            }
        )
    return summary, known_event_ids, technique_ids, event_to_techniques


def _extract_json_object(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return text[start : end + 1]


def template_result(detections: list[Detection]) -> AIModelOutput:
    """Deterministic, rule-based stand-in for an LLM: used when LLM_PROVIDER=template,
    and as the fallback any provider degrades to after a failed retry."""
    if not detections:
        return AIModelOutput(
            verdict="benign",
            confidence=0.5,
            reasoning="No detections are associated with this incident.",
            narrative="No suspicious activity was detected for this incident.",
            risk_explanation="Risk score is 0 because no rules fired.",
            findings=[],
        )

    max_risk = max(d.risk_score for d in detections)
    verdict = "malicious" if max_risk >= 60 else "suspicious" if max_risk >= 30 else "benign"
    rule_names = sorted({d.rule_name for d in detections})
    technique_names = sorted({TECHNIQUE_NAMES.get(t, t) for d in detections for t in json.loads(d.technique_ids)})

    findings = [
        AIFinding(
            technique_id=tid,
            claim=f"{d.rule_name} fired {d.event_count} time(s), matching {tid} ({TECHNIQUE_NAMES.get(tid, tid)}).",
            event_ids=json.loads(d.matched_event_ids),
        )
        for d in detections
        for tid in json.loads(d.technique_ids)
    ]

    return AIModelOutput(
        verdict=verdict,
        confidence=0.6,
        reasoning=f"{len(detections)} detection(s) fired: {', '.join(rule_names)}.",
        narrative=f"Observed {', '.join(technique_names)} activity, consistent with {', '.join(rule_names)}.",
        risk_explanation=(
            f"Highest risk score among this incident's detections is {max_risk}, computed from "
            "rule severity, confidence, and how often each rule fired."
        ),
        findings=findings,
    )


def build_recommended_actions(technique_ids: set[str]) -> list[str]:
    actions: list[str] = []
    for tid in sorted(technique_ids):
        for action in MITIGATIONS.get(tid, []):
            if action not in actions:
                actions.append(action)
    return actions


def check_rate_limit(db: Session, actor: str) -> bool:
    """Returns True if the actor is still under the hourly AI-call cap."""
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    count = (
        db.query(AuditLog)
        .filter(AuditLog.actor == actor, AuditLog.action == "ai_analyze", AuditLog.timestamp >= since)
        .count()
    )
    return count < settings.ai_calls_per_hour


def analyze_incident(
    db: Session,
    incident_id: str,
    detections: list[Detection],
    actor: str,
    client: LLMClient | None = None,
) -> AIAnalysis:
    # The chronological order, every detection's facts, and the risk scores are
    # all computed in code here - the model only ever rewrites them in words.
    ordered_detections = sorted(detections, key=lambda d: d.first_seen)
    summary, known_event_ids, technique_ids, event_to_techniques = _build_summary(ordered_detections)
    floor = _verdict_floor(_max_risk_score(ordered_detections))

    prompt_text: str | None = None
    raw_response: str | None = None
    degraded = False

    if settings.llm_provider == "template":
        provider_used = "template"
        result = template_result(ordered_detections)
    else:
        provider_used = settings.llm_provider
        client = client or get_client(settings.llm_provider)
        prompt_text = build_prompt(summary)
        result = None
        for _ in range(MAX_ATTEMPTS):
            try:
                raw_response = client.complete_json(prompt_text)
                candidate = AIModelOutput.model_validate_json(_extract_json_object(raw_response))
                if _has_disallowed_numbers(candidate):
                    raise ValueError("model output contained digits outside the computed facts")
                if _narrative_too_long(candidate):
                    raise ValueError("narrative exceeded the 5-sentence limit")
                result = candidate
                break
            except (AIProviderError, ValidationError, ValueError) as exc:
                raw_response = f"{raw_response or ''}\n<error: {exc}>"
                continue
        if result is None:
            degraded = True
            provider_used = "template"
            result = template_result(ordered_detections)

    verified_findings = merge_findings_by_technique(
        verify_findings(result.findings, known_event_ids, event_to_techniques)
    )
    actions = build_recommended_actions(technique_ids)
    final_verdict = _apply_verdict_floor(result.verdict, floor)

    analysis = AIAnalysis(
        incident_id=incident_id,
        provider=provider_used,
        degraded=degraded,
        verdict=final_verdict,
        confidence=result.confidence,
        reasoning=result.reasoning,
        narrative=result.narrative,
        risk_explanation=result.risk_explanation,
        findings=json.dumps([f.model_dump() for f in verified_findings]),
        recommended_actions=json.dumps(actions),
    )
    db.add(analysis)
    db.flush()  # assign analysis.id before creating actions that reference it

    for action_text in actions:
        db.add(Action(incident_id=incident_id, analysis_id=analysis.id, action_text=action_text))

    log_action(
        db,
        actor=actor,
        action="ai_analyze",
        detail=json.dumps(
            {
                "incident_id": incident_id,
                "provider": provider_used,
                "degraded": degraded,
                "prompt": _redact(prompt_text),
                "response": _redact(raw_response),
            }
        ),
    )

    return analysis
