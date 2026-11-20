import unittest
from math import isfinite

from src.event_schema import SecurityEvent
from src.feature_extraction import FEATURE_NAMES
from src.anomaly_detection import detect_anomalies


def make_event(event_id):
    return SecurityEvent(
        event_id=event_id,
        case_id="CASE001",
        timestamp="2026-11-20T10:00:00",
        source_type="test",
        event_type="connection",
        host="HOST01",
        user="user01",
        process_name="python.exe",
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
    )


def make_features(hour=10):
    return {
        "hour": hour,
        "day_of_week": 4,
        "is_weekend": 0,
        "has_user": 1,
        "has_host": 1,
        "has_process": 1,
        "has_source_ip": 1,
        "has_destination_ip": 1,
        "is_login_failed": 0,
        "is_login_success": 0,
        "is_process_execution": 0,
        "is_connection": 1,
        "is_other_event": 0,
    }


class TestAnomalyDetection(unittest.TestCase):

    def test_valid_events_return_results(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features(hour=10 + i) for i in range(5)]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 5)

    def test_result_schema(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features() for _ in range(5)]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(errors, [])

        for result in results:
            self.assertEqual(
                set(result.keys()),
                {
                    "event_id",
                    "is_anomaly",
                    "classification",
                    "anomaly_score",
                },
            )

    def test_event_ids_are_preserved(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features(hour=i) for i in range(5)]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(errors, [])
        self.assertEqual(
            [result["event_id"] for result in results],
            [event.event_id for event in events],
        )

    def test_anomaly_scores_are_finite(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features(hour=i) for i in range(5)]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(errors, [])

        for result in results:
            self.assertTrue(isfinite(result["anomaly_score"]))

    def test_insufficient_events_are_rejected(self):
        events = [make_event("EVT001")]
        features = [make_features()]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(results, [])
        self.assertTrue(errors)

    def test_mismatched_event_and_feature_counts(self):
        events = [make_event("EVT001"), make_event("EVT002")]
        features = [make_features()]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(results, [])
        self.assertTrue(errors)

    def test_missing_feature_is_rejected(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features() for _ in range(5)]

        del features[0]["hour"]

        results, errors = detect_anomalies(events, features)

        self.assertEqual(results, [])
        self.assertTrue(errors)

    def test_non_numeric_feature_is_rejected(self):
        events = [make_event(f"EVT{i}") for i in range(5)]
        features = [make_features() for _ in range(5)]

        features[0]["hour"] = "invalid"

        results, errors = detect_anomalies(events, features)

        self.assertEqual(results, [])
        self.assertTrue(errors)

    def test_reproducible_results(self):
        events = [make_event(f"EVT{i}") for i in range(10)]
        features = [make_features(hour=i) for i in range(10)]

        first_results, first_errors = detect_anomalies(
            events,
            features,
            random_state=42,
        )

        second_results, second_errors = detect_anomalies(
            events,
            features,
            random_state=42,
        )

        self.assertEqual(first_errors, [])
        self.assertEqual(second_errors, [])
        self.assertEqual(first_results, second_results)


if __name__ == "__main__":
    unittest.main()