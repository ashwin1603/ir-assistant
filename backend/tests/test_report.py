from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.analysis.report import IMPACT_PLAIN, TACTIC_PLAIN, attack_table, impact_text, top_actions, what_happened
from tests.test_artifacts import BASE_EVENT, COLLECTOR, _analyst, _login, _seed_incident

T0 = datetime(2026, 10, 21, 5, 0, tzinfo=timezone.utc)


def _entry(tactics, minutes, techniques=("T0000",), rule="rule", event_ids=("e1",)):
    # Same shape as build_timeline() output.
    return {
        "rule_name": rule,
        "technique_ids": list(techniques),
        "tactics": tactics,
        "first_seen": T0 + timedelta(minutes=minutes),
        "event_ids": list(event_ids),
    }


def test_what_happened_is_ordered_and_deduplicated():
    timeline = [_entry(["Execution", "Defense Evasion"], 5), _entry(["Credential Access"], 0), _entry(["Execution"], 9)]
    assert what_happened(timeline) == [
        TACTIC_PLAIN["Credential Access"],
        TACTIC_PLAIN["Execution"],
        TACTIC_PLAIN["Defense Evasion"],
    ]


def test_unknown_tactic_and_risk_level_still_give_text():
    assert "Exfiltration" in what_happened([_entry(["Exfiltration"], 0)])[0]
    assert impact_text("Critical") == IMPACT_PLAIN["Critical"]
    assert impact_text("Bogus")


def test_rdp_rule_says_enabled_not_used():
    assert TACTIC_PLAIN["Lateral Movement"] == "Remote access to the machine was enabled."


def test_plain_language_does_not_overstate():
    # Rules see commands and log entries, not proven outcomes or intent.
    text = " ".join(list(TACTIC_PLAIN.values()) + list(IMPACT_PLAIN.values())).lower()
    for phrase in ["was used", "were downloaded", "tried to hide", "someone ", "attack in progress"]:
        assert phrase not in text, phrase


def test_top_actions_show_all_statuses_and_cap_at_three():
    statuses = ["rejected", "pending", "approved"]
    actions = [SimpleNamespace(id=str(i), status=s) for i, s in enumerate(statuses)]
    assert [a.status for a in top_actions(actions)] == ["approved", "pending", "rejected"]

    many = [SimpleNamespace(id=str(i), status=s) for i, s in enumerate(["pending", "rejected", "pending", "approved", "pending"])]
    assert [a.id for a in top_actions(many)] == ["3", "0", "2"]
    assert top_actions([]) == []


def test_attack_table_merges_rows_per_technique():
    timeline = [
        _entry(["Execution"], 0, techniques=("T1059.001", "T1027"), rule="Encoded PS", event_ids=("a", "b")),
        _entry(["Execution"], 1, techniques=("T1059.001",), rule="Script block", event_ids=("b", "c")),
    ]
    rows = {r["technique_id"]: r for r in attack_table(timeline)}
    ps = rows["T1059.001"]
    assert ps["name"] == "PowerShell" and ps["tactic"] == "Execution"
    assert ps["detection_count"] == 2
    assert ps["rule_names"] == ["Encoded PS", "Script block"]
    assert ps["event_ids"] == ["a", "b", "c"]
    assert rows["T1027"]["tactic"] == "Defense Evasion"


def test_report_has_executive_and_technical_data(client, seed_users):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)

    resp = client.get(f"/api/incidents/{incident_id}/report", headers=headers)
    assert resp.status_code == 200
    report = resp.json()

    assert report["generated_by"] == "test_analyst"
    assert report["incident"]["host"] == "HOST-A"
    assert TACTIC_PLAIN["Credential Access"] in report["executive"]["what_happened"]
    assert report["executive"]["impact"] == IMPACT_PLAIN[report["incident"]["risk_level"]]
    assert ("ip", "10.0.0.5") in {(i["type"], i["value"]) for i in report["iocs"]}
    # Every timeline row carries the evidence event ids the technical view prints.
    assert all(entry["event_ids"] for entry in report["incident"]["timeline"])
    assert "T1110" in {row["technique_id"] for row in report["attack"]}


def test_report_viewer_allowed_anonymous_rejected(client, seed_users):
    incident_id = _seed_incident(client, _analyst(client))
    viewer = _login(client, "test_viewer", "TestViewerPass123!")

    assert client.get(f"/api/incidents/{incident_id}/report", headers=viewer).status_code == 200
    assert client.get(f"/api/incidents/{incident_id}/report").status_code == 401
    assert client.get("/api/incidents/does-not-exist/report", headers=viewer).status_code == 404


def test_report_without_analysis_has_no_top_actions(client, seed_users):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)
    report = client.get(f"/api/incidents/{incident_id}/report", headers=headers).json()
    # The UI then shows "Run AI analysis to generate recommendations".
    assert report["executive"]["top_actions"] == []


def test_report_top_actions_carry_status_after_analysis(client, seed_users):
    headers = _analyst(client)
    incident_id = _seed_incident(client, headers)
    assert client.post(f"/api/incidents/{incident_id}/analyze", headers=headers).status_code == 200
    actions = client.get("/api/actions", headers=headers).json()
    client.post(f"/api/actions/{actions[0]['id']}/reject", headers=headers)

    top = client.get(f"/api/incidents/{incident_id}/report", headers=headers).json()["executive"]["top_actions"]
    assert 1 <= len(top) <= 3
    assert {a["status"] for a in top} <= {"pending", "approved", "rejected"}
    assert all(a["action_text"] for a in top)


def test_report_simulated_flag(client, seed_users):
    headers = _analyst(client)
    real_id = _seed_incident(client, headers)
    assert client.get(f"/api/incidents/{real_id}/report", headers=headers).json()["simulated"] is False

    sim = [
        {**BASE_EVENT, "source": "simulated", "host": "SIM-HOST",
         "id": f"e000000{i}-0000-0000-0000-000000000000", "timestamp": f"2026-10-21T07:00:0{i}+00:00"}
        for i in range(5)
    ]
    assert client.post("/api/events/ingest", json={"events": sim}, headers=COLLECTOR).status_code == 201
    sim_id = next(i["id"] for i in client.get("/api/incidents", headers=headers).json() if i["host"] == "SIM-HOST")
    assert client.get(f"/api/incidents/{sim_id}/report", headers=headers).json()["simulated"] is True
