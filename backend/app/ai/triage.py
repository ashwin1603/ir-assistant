"""Orchestrates AI analysis of an incident. Every fact shown to the analyst -
verdict, confidence, reasoning, risk explanation, findings, recommended
actions - is computed deterministically in code from the rule engine's own
output (see template_result()). The only thing ever asked of the LLM is a
short narrative paraphrase of the highest-risk detections; if that fails,
times out, or breaks a rule, the deterministic narrative is used instead.
This keeps "rules detect, AI reasons" true even when the model degrades, and
keeps the model's job small enough to finish well under the UI's time budget."""

import hashlib
import json
import re

from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.ai.client import AIProviderError, LLMClient, get_client
from app.ai.prompts import build_prompt
from app.ai.verify import AIFinding, AIModelOutput, AINarrativeOutput, merge_findings_by_technique, verify_findings
from app.audit import log_action
from app.config import settings
from app.detection.attack_map import MITIGATIONS, TECHNIQUE_NAMES
from app.models import Action, AIAnalysis, AuditLog, Detection

MAX_ATTEMPTS = 2  # one try + one retry, then fall back to the deterministic narrative
TOP_DETECTIONS_FOR_NARRATIVE = 5  # only the highest-risk detections are sent to the model

_SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|bearer|authorization)\S*[:=]\s*\S+")
_DIGIT_PATTERN = re.compile(r"\d")
_SENTENCE_SPLIT_PATTERN = re.compile(r"[.!?]+")
MAX_NARRATIVE_SENTENCES = 3


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


def _narrative_summary(detections: list[Detection]) -> list[dict]:
    """What actually gets sent to the model: only the highest-risk detections,
    only the fields needed to write a sentence or two - no event ids, counts,
    or exact scores, so there's nothing for the model to invent a number from."""
    top = sorted(detections, key=lambda d: d.risk_score, reverse=True)[:TOP_DETECTIONS_FOR_NARRATIVE]
    return [
        {
            "rule_name": d.rule_name,
            "technique_ids": json.loads(d.technique_ids),
            "tactics": json.loads(d.tactics),
            "risk_level": d.risk_level,
        }
        for d in top
    ]


def _extract_json_object(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return text[start : end + 1]


def _narrative_invalid_reason(narrative: str) -> str | None:
    """All numeric facts are computed in code and shown in the UI separately;
    a digit in the model's prose means it invented or restated a number it
    could get wrong. Returns why the narrative is unusable, or None if it's fine."""
    if _DIGIT_PATTERN.search(narrative):
        return "narrative contained digits"
    sentences = [s for s in _SENTENCE_SPLIT_PATTERN.split(narrative) if s.strip()]
    if len(sentences) > MAX_NARRATIVE_SENTENCES:
        return f"narrative exceeded the {MAX_NARRATIVE_SENTENCES}-sentence limit"
    return None


def _redact(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    return _SECRET_PATTERN.sub(r"\1=[REDACTED]", text)[:limit]


def template_result(detections: list[Detection]) -> AIModelOutput:
    """Deterministic, rule-based result: verdict, confidence, reasoning, risk
    explanation, findings, and the default narrative are always built this
    way. Used as-is when LLM_PROVIDER=template, as the fallback narrative
    source when a provider degrades, and as the base every provider's
    narrative gets grafted onto otherwise."""
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


def _detections_hash(detections: list[Detection]) -> str:
    """Stable fingerprint of this incident's current detection set. Detection
    ids are content-addressed (same events -> same id), so this is unchanged
    across repeat requests until a detection is added, removed, or its
    matched events change - that's the cache invalidation signal."""
    ids = sorted(d.id for d in detections)
    return hashlib.sha256(",".join(ids).encode()).hexdigest()


def analyze_incident(
    db: Session,
    incident_id: str,
    detections: list[Detection],
    actor: str,
    client: LLMClient | None = None,
) -> AIAnalysis:
    ordered_detections = sorted(detections, key=lambda d: d.first_seen)
    detections_hash = _detections_hash(ordered_detections)

    cached = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.incident_id == incident_id, AIAnalysis.detections_hash == detections_hash)
        .order_by(AIAnalysis.created_at.desc())
        .first()
    )
    if cached:
        log_action(db, actor=actor, action="ai_analyze_cached", detail=json.dumps({"incident_id": incident_id}))
        return cached

    # The chronological order and every detection's facts are computed in
    # code here - the model, if used at all, only ever paraphrases a subset.
    _, known_event_ids, technique_ids, event_to_techniques = _build_summary(ordered_detections)
    result = template_result(ordered_detections)

    prompt_text: str | None = None
    raw_response: str | None = None
    degraded = False

    if settings.llm_provider == "template":
        provider_used = "template"
    else:
        provider_used = settings.llm_provider
        client = client or get_client(settings.llm_provider)
        prompt_text = build_prompt(_narrative_summary(ordered_detections))
        narrative = None
        for _ in range(MAX_ATTEMPTS):
            try:
                raw_response = client.complete_json(prompt_text)
                candidate = AINarrativeOutput.model_validate_json(_extract_json_object(raw_response))
                reason = _narrative_invalid_reason(candidate.narrative)
                if reason:
                    raise ValueError(reason)
                narrative = candidate.narrative
                break
            except (AIProviderError, ValidationError, ValueError) as exc:
                raw_response = f"{raw_response or ''}\n<error: {exc}>"
                continue
        if narrative is None:
            degraded = True
            provider_used = "template (fallback)"
        else:
            result = result.model_copy(update={"narrative": narrative})

    verified_findings = merge_findings_by_technique(
        verify_findings(result.findings, known_event_ids, event_to_techniques)
    )
    actions = build_recommended_actions(technique_ids)

    analysis = AIAnalysis(
        incident_id=incident_id,
        detections_hash=detections_hash,
        provider=provider_used,
        degraded=degraded,
        verdict=result.verdict,
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
