"""Validates the LLM's structured output, then verifies each finding's
evidence: a finding is dropped if it cites an event id the incident doesn't
have, or pairs a technique id with an event that doesn't belong to it."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AIFinding(BaseModel):
    technique_id: str = Field(max_length=32)
    claim: str = Field(max_length=2000)
    event_ids: list[str] = Field(min_length=1, max_length=50)


class AIModelOutput(BaseModel):
    """The deterministic analysis result shown to the analyst. Despite the
    name, the model itself no longer fills this in - template_result() builds
    it from code, and the model may only supply a replacement narrative (see
    AINarrativeOutput)."""

    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0, le=1)
    reasoning: str = Field(max_length=4000)
    narrative: str = Field(max_length=4000)
    risk_explanation: str = Field(max_length=2000)
    findings: list[AIFinding] = Field(default_factory=list, max_length=50)

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, value):
        return value.strip().lower() if isinstance(value, str) else value


class AINarrativeOutput(BaseModel):
    """The only thing actually asked of the LLM: a short paraphrase of the
    detections. Everything else in AIModelOutput is code-computed."""

    narrative: str = Field(max_length=1000)


def verify_findings(
    findings: list[AIFinding],
    known_event_ids: set[str],
    event_to_techniques: dict[str, set[str]],
) -> list[AIFinding]:
    verified = []
    for finding in findings:
        if not all(event_id in known_event_ids for event_id in finding.event_ids):
            continue  # cites an id that doesn't exist in this incident's evidence
        if not all(finding.technique_id in event_to_techniques.get(event_id, set()) for event_id in finding.event_ids):
            continue  # technique claimed doesn't match what the cited event actually triggered
        verified.append(finding)
    return verified


def merge_findings_by_technique(findings: list[AIFinding]) -> list[AIFinding]:
    """Collapse multiple findings for the same technique (e.g. one per detection
    that fired it) into a single finding per technique, with evidence unioned."""
    merged: dict[str, AIFinding] = {}
    for finding in findings:
        existing = merged.get(finding.technique_id)
        if existing is None:
            merged[finding.technique_id] = finding.model_copy(update={"event_ids": list(finding.event_ids)})
        else:
            existing.event_ids.extend(eid for eid in finding.event_ids if eid not in existing.event_ids)
    return list(merged.values())
