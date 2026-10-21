import json
import uuid
from datetime import datetime, timedelta, timezone

from app.ai.client import AIProviderError, LLMClient
from app.ai.triage import analyze_incident, check_rate_limit
from app.ai.verify import AIFinding, merge_findings_by_technique, verify_findings
from app.config import settings
from app.models import AuditLog, Detection

BASE_TIME = datetime(2026, 10, 21, 5, 0, 0)


def _detection(rule_name, technique_ids, event_ids, **overrides):
    defaults = dict(
        id=str(uuid.uuid4()),
        incident_id=None,
        rule_name=rule_name,
        technique_ids=json.dumps(technique_ids),
        tactics=json.dumps(["Credential Access"]),
        severity=6,
        confidence=0.9,
        host="HOST-A",
        matched_event_ids=json.dumps(event_ids),
        event_count=len(event_ids),
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        risk_score=70.0,
        risk_level="High",
    )
    defaults.update(overrides)
    return Detection(**defaults)


def _brute_force_events():
    events = []
    for i in range(5):
        events.append(
            {
                "id": f"a000000{i}-0000-0000-0000-000000000000",
                "source": "agent",
                "host": "HOST-A",
                "timestamp": f"2026-10-21T05:00:0{i}+00:00",
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": 4625,
                "user": "fakeuser",
                "process": None,
                "command_line": None,
                "parent_process": None,
                "src_ip": "10.0.0.5",
                "logon_type": "3",
                "message": "An account failed to log on.",
                "raw": "{}",
            }
        )
    return events


def _login(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class FakeClient(LLMClient):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete_json(self, prompt: str) -> str:
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


# ---- verify.py -------------------------------------------------------------


def test_verify_drops_finding_with_unknown_event_id():
    findings = [AIFinding(technique_id="T1110", claim="brute force", event_ids=["evt-1", "evt-unknown"])]
    survivors = verify_findings(findings, known_event_ids={"evt-1", "evt-2"}, event_to_techniques={"evt-1": {"T1110"}})
    assert survivors == []


def test_verify_drops_finding_with_mismatched_technique():
    findings = [AIFinding(technique_id="T1098", claim="wrong technique for this event", event_ids=["evt-1"])]
    survivors = verify_findings(findings, known_event_ids={"evt-1"}, event_to_techniques={"evt-1": {"T1110"}})
    assert survivors == []


def test_verify_keeps_valid_finding():
    findings = [AIFinding(technique_id="T1110", claim="brute force confirmed", event_ids=["evt-1", "evt-2"])]
    survivors = verify_findings(
        findings,
        known_event_ids={"evt-1", "evt-2"},
        event_to_techniques={"evt-1": {"T1110"}, "evt-2": {"T1110"}},
    )
    assert len(survivors) == 1


def test_merge_findings_by_technique_unions_evidence_into_one_finding():
    findings = [
        AIFinding(technique_id="T1110", claim="first detection", event_ids=["evt-1"]),
        AIFinding(technique_id="T1110", claim="second detection", event_ids=["evt-2", "evt-1"]),
        AIFinding(technique_id="T1098", claim="unrelated technique", event_ids=["evt-3"]),
    ]
    merged = merge_findings_by_technique(findings)

    assert len(merged) == 2
    t1110 = next(f for f in merged if f.technique_id == "T1110")
    assert set(t1110.event_ids) == {"evt-1", "evt-2"}


# ---- triage.py: summary never leaks raw event fields -----------------------


def test_summary_sent_to_model_excludes_raw_event_fields(db_session):
    from app.ai.triage import _build_summary

    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])
    summary, known_ids, technique_ids, event_to_techniques = _build_summary([detection])

    assert known_ids == {"evt-1"}
    assert technique_ids == {"T1110"}
    assert event_to_techniques == {"evt-1": {"T1110"}}
    keys = set(summary[0].keys())
    assert "command_line" not in keys
    assert "message" not in keys
    assert "user" not in keys


# ---- triage.py: template provider (default, no network) --------------------


def test_template_provider_produces_verified_findings_and_playbook_actions(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "template")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1", "evt-2"])

    analysis = analyze_incident(db_session, incident_id="inc-1", detections=[detection], actor="test_analyst")

    assert analysis.provider == "template"
    assert analysis.degraded is False
    assert analysis.verdict in {"benign", "suspicious", "malicious"}
    findings = json.loads(analysis.findings)
    assert len(findings) == 1
    assert set(findings[0]["event_ids"]) == {"evt-1", "evt-2"}
    actions = json.loads(analysis.recommended_actions)
    assert any("lockout" in a.lower() or "mfa" in a.lower() for a in actions)


def test_template_provider_handles_incident_with_no_detections(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "template")

    analysis = analyze_incident(db_session, incident_id="inc-empty", detections=[], actor="test_analyst")

    assert analysis.verdict == "benign"
    assert json.loads(analysis.findings) == []


# ---- triage.py: ollama provider only ever supplies a narrative ------------
# verdict, confidence, reasoning, risk_explanation, and findings always come
# from template_result() (code), regardless of provider - see analyze_incident.


def test_ollama_narrative_used_when_valid(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])

    good = json.dumps({"narrative": "A brute force attempt against a single account was observed."})
    client = FakeClient([good])

    analysis = analyze_incident(db_session, incident_id="inc-1", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 1
    assert analysis.provider == "ollama"
    assert analysis.degraded is False
    assert analysis.narrative == "A brute force attempt against a single account was observed."
    # verdict/reasoning/findings are unaffected by the model and come from the template
    assert analysis.verdict == "malicious"  # risk_score=70.0 (default) -> >= 60
    findings = json.loads(analysis.findings)
    assert len(findings) == 1


def test_ollama_succeeds_on_retry_after_bad_first_response(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])

    good = json.dumps({"narrative": "Repeated failed logons were observed against one account."})
    client = FakeClient(["not json at all", good])

    analysis = analyze_incident(db_session, incident_id="inc-2", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 2
    assert analysis.provider == "ollama"
    assert analysis.degraded is False


def test_ollama_falls_back_to_template_after_two_failures(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])

    client = FakeClient([AIProviderError("connection refused"), "still not json"])

    analysis = analyze_incident(db_session, incident_id="inc-3", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 2
    assert analysis.provider == "template (fallback)"
    assert analysis.degraded is True
    # falls back to the deterministic narrative, not an empty one
    assert "Brute force logon" in analysis.narrative


def test_model_narrative_with_digits_falls_back_to_template(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])

    has_numbers = json.dumps({"narrative": "5 failed logons were observed against one account."})
    client = FakeClient([has_numbers, has_numbers])

    analysis = analyze_incident(db_session, incident_id="inc-digits", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 2
    assert analysis.provider == "template (fallback)"
    assert analysis.degraded is True


def test_model_narrative_over_three_sentences_falls_back_to_template(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])

    too_long = json.dumps({"narrative": "Sentence one. Sentence two. Sentence three. Sentence four."})
    client = FakeClient([too_long, too_long])

    analysis = analyze_incident(db_session, incident_id="inc-long", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 2
    assert analysis.provider == "template (fallback)"
    assert analysis.degraded is True


def test_audit_log_stores_redacted_prompt_and_response(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])
    leaky = json.dumps({"narrative": "api_key=sk-super-secret-value should never be stored"})
    client = FakeClient([leaky])

    analyze_incident(db_session, incident_id="inc-5", detections=[detection], actor="test_analyst", client=client)

    entry = db_session.query(AuditLog).filter(AuditLog.action == "ai_analyze").one()
    assert "sk-super-secret-value" not in entry.detail
    assert "REDACTED" in entry.detail


# ---- triage.py: only the top 5 highest-risk detections go to the model ----


def test_narrative_summary_caps_at_five_highest_risk_detections():
    from app.ai.triage import _narrative_summary

    detections = [
        _detection(f"Rule {i}", ["T1110"], [f"evt-{i}"], risk_score=float(i), id=f"det-{i}")
        for i in range(8)
    ]

    summary = _narrative_summary(detections)

    assert len(summary) == 5
    assert [d["rule_name"] for d in summary] == ["Rule 7", "Rule 6", "Rule 5", "Rule 4", "Rule 3"]
    assert set(summary[0].keys()) == {"rule_name", "technique_ids", "tactics", "risk_level"}


# ---- triage.py: cache result per incident until its detections change -----


def test_second_analyze_call_is_served_from_cache(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection = _detection("Brute force logon", ["T1110"], ["evt-1"])
    client = FakeClient([json.dumps({"narrative": "Repeated failed logons were observed."})])

    first = analyze_incident(db_session, incident_id="inc-cache", detections=[detection], actor="test_analyst", client=client)
    second = analyze_incident(db_session, incident_id="inc-cache", detections=[detection], actor="test_analyst", client=client)

    assert client.calls == 1  # the model was not called again
    assert second.id == first.id
    cache_hits = db_session.query(AuditLog).filter(AuditLog.action == "ai_analyze_cached").count()
    assert cache_hits == 1


def test_analyze_call_is_not_cached_when_detections_change(db_session, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    detection_a = _detection("Brute force logon", ["T1110"], ["evt-1"])
    detection_b = _detection("Added to Administrators", ["T1098"], ["evt-2"])
    client = FakeClient(
        [
            json.dumps({"narrative": "Repeated failed logons were observed."}),
            json.dumps({"narrative": "A user was added to a privileged group."}),
        ]
    )

    analyze_incident(db_session, incident_id="inc-change", detections=[detection_a], actor="test_analyst", client=client)
    second = analyze_incident(
        db_session, incident_id="inc-change", detections=[detection_a, detection_b], actor="test_analyst", client=client
    )

    assert client.calls == 2  # new detection set -> re-analyzed
    assert second.degraded is False


# ---- rate limiting -----------------------------------------------------


def test_rate_limit_blocks_after_cap(db_session, monkeypatch):
    monkeypatch.setattr(settings, "ai_calls_per_hour", 1)
    db_session.add(AuditLog(actor="test_analyst", action="ai_analyze", detail="{}"))
    db_session.commit()

    assert check_rate_limit(db_session, "test_analyst") is False
    assert check_rate_limit(db_session, "someone_else") is True


def test_rate_limit_ignores_calls_older_than_an_hour(db_session, monkeypatch):
    monkeypatch.setattr(settings, "ai_calls_per_hour", 1)
    old = AuditLog(actor="test_analyst", action="ai_analyze", detail="{}")
    old.timestamp = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.add(old)
    db_session.commit()

    assert check_rate_limit(db_session, "test_analyst") is True


# ---- route-level behaviour ----------------------------------------------


def test_analyze_route_requires_auth(client):
    resp = client.post("/api/incidents/does-not-exist/analyze")
    assert resp.status_code == 401


def test_analyze_route_forbidden_for_viewer(client, seed_users):
    headers = _login(client, "test_viewer", "TestViewerPass123!")
    resp = client.post("/api/incidents/does-not-exist/analyze", headers=headers)
    assert resp.status_code == 403


def test_analyze_route_404_for_unknown_incident(client, seed_users):
    headers = _login(client, "test_analyst", "TestAnalystPass123!")
    resp = client.post("/api/incidents/does-not-exist/analyze", headers=headers)
    assert resp.status_code == 404


def test_analyze_route_end_to_end_with_template_provider(client, seed_users, monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "template")
    client.post(
        "/api/events/ingest",
        json={"events": _brute_force_events()},
        headers={"X-Collector-Key": "test-collector-key"},
    )
    headers = _login(client, "test_analyst", "TestAnalystPass123!")
    incident_id = client.get("/api/incidents", headers=headers).json()[0]["id"]

    resp = client.post(f"/api/incidents/{incident_id}/analyze", headers=headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "template"
    assert body["degraded"] is False
    assert body["verdict"] in {"benign", "suspicious", "malicious"}
    assert len(body["findings"]) == 1
    assert len(body["recommended_actions"]) > 0
