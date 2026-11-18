
import unittest
import tempfile
import csv
from pathlib import Path

from src.event_ingestion import load_events_from_csv


class TestEventIngestion(unittest.TestCase):

    def test_sample_dataset_loads(self):
        events, errors = load_events_from_csv(
            "data/raw/sample_events.csv",
            expected_case_id="CASE001"
        )

        self.assertEqual(len(events), 8)
        self.assertEqual(len(errors), 0)

    def test_events_are_normalized(self):
        events, errors = load_events_from_csv(
            "data/raw/sample_events.csv"
        )

        self.assertEqual(events[0].event_id, "EVT001")
        self.assertEqual(events[0].event_type, "login_success")
        self.assertIsNone(events[0].process_name)

    def test_custom_column_mapping(self):
        rows = [
            {
                "Event ID": "E001",
                "Investigation": "CASE002",
                "Date": "2026-11-16T10:00:00",
                "Log Source": "windows",
                "Activity": "login_failed",
                "Username": "admin",
            }
        ]

        mapping = {
            "event_id": "Event ID",
            "case_id": "Investigation",
            "timestamp": "Date",
            "source_type": "Log Source",
            "event_type": "Activity",
            "user": "Username",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "custom_events.csv"

            with csv_path.open(
                "w", newline="", encoding="utf-8"
            ) as file:
                writer = csv.DictWriter(
                    file, fieldnames=rows[0].keys()
                )
                writer.writeheader()
                writer.writerows(rows)

            events, errors = load_events_from_csv(
                str(csv_path),
                expected_case_id="CASE002",
                column_mapping=mapping,
            )

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, "E001")
        self.assertEqual(events[0].case_id, "CASE002")
        self.assertEqual(events[0].event_type, "login_failed")
        self.assertEqual(events[0].user, "admin")

    def test_missing_required_mapping_is_rejected(self):
        mapping = {
            "event_id": "Event ID",
            "case_id": "Investigation",
            "timestamp": "Date",
            "source_type": "Log Source",
        }

        with self.assertRaises(ValueError):
            load_events_from_csv(
                "data/raw/sample_events.csv",
                column_mapping=mapping,
            )


if __name__ == "__main__":
    unittest.main()


