
import unittest

from src.event_ingestion import load_events_from_csv
from src.detection_engine import (
    detect_brute_force_followed_by_success
)


class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.events, self.errors = load_events_from_csv(
            "data/raw/sample_events.csv",
            "CASE001"
        )

    def test_detects_failed_logins_followed_by_success(self):
        alerts = detect_brute_force_followed_by_success(
            self.events
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempt_count"], 3)
        self.assertEqual(alerts[0]["success_event_id"], "EVT005")
        self.assertEqual(
            alerts[0]["failed_event_ids"],
            ["EVT002", "EVT003", "EVT004"]
        )

    def test_no_alert_when_failures_below_threshold(self):
        events = self.events[:4]

        alerts = detect_brute_force_followed_by_success(
            events
        )

        self.assertEqual(alerts, [])

    def test_no_alert_when_ip_does_not_match(self):
        events = self.events[:5]

        events[3].source_ip = "198.51.100.20"

        alerts = detect_brute_force_followed_by_success(
            events
        )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()

