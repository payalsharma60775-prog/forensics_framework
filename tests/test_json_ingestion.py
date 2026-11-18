
import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.json_adapter import load_events_from_json


class TestJSONIngestion(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "events.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_json(self, data):
        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(data, file)

    def sample_event(self):
        return {
            "event_id": "EVT101",
            "case_id": "CASE001",
            "timestamp": "2026-11-18T10:30:00",
            "source_type": "windows",
            "event_type": "login_failed",
            "host": "WORKSTATION01",
            "user": "admin",
            "source_ip": "203.0.113.25",
        }

    def test_json_array(self):
        self.write_json([self.sample_event()])

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].event_id, "EVT101")

    def test_json_events_object(self):
        self.write_json({
            "events": [self.sample_event()]
        })

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])

    def test_single_json_event(self):
        self.write_json(self.sample_event())

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])

    def test_custom_field_mapping(self):
        event = {
            "id": "EVT102",
            "investigation": "CASE001",
            "time": "2026-11-18T11:00:00",
            "source": "windows",
            "action": "login_success",
        }

        self.write_json([event])

        mapping = {
            "event_id": "id",
            "case_id": "investigation",
            "timestamp": "time",
            "source_type": "source",
            "event_type": "action",
        }

        events, errors = load_events_from_json(
            self.file_path,
            column_mapping=mapping
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].event_type, "login_success")

    def test_missing_required_field(self):
        event = self.sample_event()
        del event["event_type"]

        self.write_json([event])

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 0)
        self.assertTrue(errors)

    def test_invalid_timestamp(self):
        event = self.sample_event()
        event["timestamp"] = "not-a-timestamp"

        self.write_json([event])

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 0)
        self.assertTrue(errors)

    def test_duplicate_event_ids(self):
        event = self.sample_event()

        self.write_json([event, event])

        events, errors = load_events_from_json(self.file_path)

        self.assertEqual(len(events), 1)
        self.assertTrue(errors)

    def test_wrong_case_id(self):
        self.write_json([self.sample_event()])

        events, errors = load_events_from_json(
            self.file_path,
            expected_case_id="CASE999"
        )

        self.assertEqual(len(events), 0)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
