from app.collector.windows_events import max_events_for


def test_max_events_for_process_creation():
    assert max_events_for(4688) == 500


def test_max_events_for_other_ids_uses_default():
    for event_id in (4625, 4720, 4732, 4698, 1102, 104, 7045, 4104):
        assert max_events_for(event_id) == 500
