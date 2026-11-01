
import unittest

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


if __name__ == "__main__":
    unittest.main()
