
import unittest

from src.event_ingestion import load_events_from_csv
from src.detection_engine import (
    detect_brute_force_followed_by_success
)
from src.correlation_engine import correlate_alerts_with_events


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.events, self.errors = load_events_from_csv(
            "data/raw/sample_events.csv",
            "CASE001"
        )

        self.alerts = detect_brute_force_followed_by_success(
            self.events
        )

    def test_correlates_process_and_network_events(self):
        results = correlate_alerts_with_events(
            self.alerts,
            self.events
        )

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0]["related_event_count"],
            2
        )

        related_ids = [
            event["event_id"]
            for event in results[0]["related_events"]
        ]

        self.assertIn("EVT006", related_ids)
        self.assertIn("EVT007", related_ids)

    def test_no_correlation_without_alerts(self):
        results = correlate_alerts_with_events(
            [],
            self.events
        )

        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
