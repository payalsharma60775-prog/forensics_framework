
import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.jsonl_adapter import load_events_from_jsonl


class TestJSONLIngestion(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "events.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_jsonl(self, lines):
        self.file_path.write_text(
            "\n".join(lines),
            encoding="utf-8"
        )

    def test_valid_jsonl_events(self):
        records = [
            {
                "event_id": "EVT001",
                "case_id": "CASE001",
                "timestamp": "2026-11-19T10:00:00",
                "source_type": "auth",
                "event_type": "login_failed",
                "user": "admin",
            },
            {
                "event_id": "EVT002",
                "case_id": "CASE001",
                "timestamp": "2026-11-19T10:01:00",
                "source_type": "auth",
                "event_type": "login_success",
                "user": "admin",
            },
        ]

        self.write_jsonl([
            json.dumps(record) for record in records
        ])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(len(events), 2)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].event_id, "EVT001")
        self.assertEqual(events[1].event_type, "login_success")

    def test_malformed_line_does_not_stop_ingestion(self):
        valid_record = {
            "event_id": "EVT001",
            "case_id": "CASE001",
            "timestamp": "2026-11-19T10:00:00",
            "source_type": "auth",
            "event_type": "login_failed",
        }

        self.write_jsonl([
            json.dumps(valid_record),
            '{"event_id": broken json',
            json.dumps({
                **valid_record,
                "event_id": "EVT002",
                "timestamp": "2026-11-19T10:01:00",
            }),
        ])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(len(events), 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("Line 2", errors[0])

    def test_missing_required_field(self):
        record = {
            "event_id": "EVT001",
            "case_id": "CASE001",
            "timestamp": "2026-11-19T10:00:00",
            "source_type": "auth",
        }

        self.write_jsonl([json.dumps(record)])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("event_type", errors[0])

    def test_invalid_timestamp(self):
        record = {
            "event_id": "EVT001",
            "case_id": "CASE001",
            "timestamp": "not-a-timestamp",
            "source_type": "auth",
            "event_type": "login_failed",
        }

        self.write_jsonl([json.dumps(record)])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("invalid ISO timestamp", errors[0])

    def test_duplicate_event_ids(self):
        record = {
            "event_id": "EVT001",
            "case_id": "CASE001",
            "timestamp": "2026-11-19T10:00:00",
            "source_type": "auth",
            "event_type": "login_failed",
        }

        self.write_jsonl([
            json.dumps(record),
            json.dumps({
                **record,
                "timestamp": "2026-11-19T10:01:00",
            }),
        ])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate event ID", errors[0])

    def test_custom_field_mapping(self):
        record = {
            "id": "EVT001",
            "case": "CASE001",
            "time": "2026-11-19T10:00:00",
            "log_source": "auth",
            "action": "login_failed",
        }

        self.write_jsonl([json.dumps(record)])

        mapping = {
            "event_id": "id",
            "case_id": "case",
            "timestamp": "time",
            "source_type": "log_source",
            "event_type": "action",
        }

        events, errors = load_events_from_jsonl(
            self.file_path,
            column_mapping=mapping
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].event_id, "EVT001")
        self.assertEqual(events[0].event_type, "login_failed")

    def test_wrong_case_id(self):
        record = {
            "event_id": "EVT001",
            "case_id": "CASE002",
            "timestamp": "2026-11-19T10:00:00",
            "source_type": "auth",
            "event_type": "login_failed",
        }

        self.write_jsonl([json.dumps(record)])

        events, errors = load_events_from_jsonl(
            self.file_path,
            expected_case_id="CASE001"
        )

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("does not match expected case", errors[0])

    def test_blank_lines_are_ignored(self):
        record = {
            "event_id": "EVT001",
            "case_id": "CASE001",
            "timestamp": "2026-11-19T10:00:00",
            "source_type": "auth",
            "event_type": "login_failed",
        }

        self.write_jsonl([
            "",
            json.dumps(record),
            "",
        ])

        events, errors = load_events_from_jsonl(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
