import unittest

from src.event_schema import SecurityEvent
from src.timeline_engine import build_event_timeline


def make_event(
    event_id,
    timestamp,
    event_type="connection",
    host="HOST01",
    user="analyst",
    process_name=None,
    source_ip=None,
    destination_ip=None,
    raw_event=None,
):
    return SecurityEvent(
        event_id=event_id,
        case_id="CASE001",
        timestamp=timestamp,
        source_type="test",
        event_type=event_type,
        host=host,
        user=user,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        raw_event=raw_event,
    )


class TestTimelineEngine(unittest.TestCase):

    def test_events_are_sorted_chronologically(self):
        events = [
            make_event("EVT003", "2026-10-31T09:20:00"),
            make_event("EVT001", "2026-10-31T09:00:00"),
            make_event("EVT002", "2026-10-31T09:10:00"),
        ]

        timeline, errors = build_event_timeline(events)

        self.assertEqual(
            [entry["event_id"] for entry in timeline],
            ["EVT001", "EVT002", "EVT003"]
        )
        self.assertEqual(errors, [])

    def test_timezone_offsets_are_normalized_to_utc(self):
        events = [
            make_event(
                "EVT002",
                "2026-10-31T14:30:00+05:30"
            ),
            make_event(
                "EVT001",
                "2026-10-31T09:00:00Z"
            ),
        ]

        timeline, errors = build_event_timeline(events)

        self.assertEqual(
            [entry["event_id"] for entry in timeline],
            ["EVT001", "EVT002"]
        )

        self.assertEqual(
            timeline[1]["timestamp"],
            "2026-10-31T09:00:00+00:00"
        )

        self.assertEqual(errors, [])

    def test_naive_timestamp_is_treated_as_utc(self):
        events = [
            make_event("EVT001", "2026-10-31T09:00:00")
        ]

        timeline, errors = build_event_timeline(events)

        self.assertEqual(
            timeline[0]["timestamp"],
            "2026-10-31T09:00:00+00:00"
        )
        self.assertEqual(errors, [])

    def test_invalid_timestamp_is_skipped_and_reported(self):
        events = [
            make_event("EVT001", "invalid-timestamp"),
            make_event("EVT002", "2026-10-31T09:10:00"),
        ]

        timeline, errors = build_event_timeline(events)

        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["event_id"], "EVT002")
        self.assertEqual(len(errors), 1)
        self.assertIn("EVT001", errors[0])

    def test_empty_input_returns_empty_results(self):
        timeline, errors = build_event_timeline([])

        self.assertEqual(timeline, [])
        self.assertEqual(errors, [])

    def test_timeline_preserves_event_context(self):
        events = [
            make_event(
                event_id="EVT001",
                timestamp="2026-10-31T09:10:00",
                event_type="process_execution",
                host="WORKSTATION01",
                user="admin",
                process_name="powershell.exe",
                source_ip="192.168.1.10",
                destination_ip="203.0.113.25",
                raw_event="PowerShell execution",
            )
        ]

        timeline, errors = build_event_timeline(events)

        entry = timeline[0]

        self.assertEqual(entry["event_id"], "EVT001")
        self.assertEqual(entry["event_type"], "process_execution")
        self.assertEqual(entry["host"], "WORKSTATION01")
        self.assertEqual(entry["user"], "admin")
        self.assertEqual(entry["process_name"], "powershell.exe")
        self.assertEqual(entry["source_ip"], "192.168.1.10")
        self.assertEqual(entry["destination_ip"], "203.0.113.25")
        self.assertEqual(entry["raw_event"], "PowerShell execution")
        self.assertEqual(errors, [])

    def test_same_timestamp_has_deterministic_order(self):
        events = [
            make_event("EVT003", "2026-10-31T09:00:00"),
            make_event("EVT001", "2026-10-31T09:00:00"),
            make_event("EVT002", "2026-10-31T09:00:00"),
        ]

        timeline, errors = build_event_timeline(events)

        self.assertEqual(
            [entry["event_id"] for entry in timeline],
            ["EVT001", "EVT002", "EVT003"]
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()