import unittest

from src.event_schema import SecurityEvent
from src.feature_extraction import extract_features, FEATURE_NAMES


def make_event(
    event_id="EVT001",
    timestamp="2026-11-21T14:30:00",
    event_type="login_failed",
    user="admin",
    host="SERVER01",
    process_name="powershell.exe",
    source_ip="192.168.1.10",
    destination_ip="192.168.1.20",
):
    return SecurityEvent(
        event_id=event_id,
        case_id="CASE001",
        timestamp=timestamp,
        source_type="windows_log",
        event_type=event_type,
        user=user,
        host=host,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )


class TestFeatureExtraction(unittest.TestCase):

    def test_valid_event_extracts_features(self):
        event = make_event()

        features, errors = extract_features([event])

        self.assertEqual(len(features), 1)
        self.assertEqual(errors, [])
        self.assertEqual(features[0]["hour"], 14)
        self.assertEqual(features[0]["day_of_week"], 5)
        self.assertEqual(features[0]["is_weekend"], 1)
        self.assertEqual(features[0]["is_login_failed"], 1)

    def test_missing_optional_fields(self):
        event = make_event(
            user=None,
            host=None,
            process_name=None,
            source_ip=None,
            destination_ip=None,
        )

        features, errors = extract_features([event])

        self.assertEqual(errors, [])
        self.assertEqual(features[0]["has_user"], 0)
        self.assertEqual(features[0]["has_host"], 0)
        self.assertEqual(features[0]["has_process"], 0)
        self.assertEqual(features[0]["has_source_ip"], 0)
        self.assertEqual(features[0]["has_destination_ip"], 0)

    def test_login_failed_feature(self):
        event = make_event(event_type="login_failed")

        features, errors = extract_features([event])

        self.assertEqual(errors, [])
        self.assertEqual(features[0]["is_login_failed"], 1)
        self.assertEqual(features[0]["is_login_success"], 0)

    def test_process_execution_feature(self):
        event = make_event(event_type="process_execution")

        features, errors = extract_features([event])

        self.assertEqual(errors, [])
        self.assertEqual(features[0]["is_process_execution"], 1)

    def test_connection_feature(self):
        event = make_event(event_type="connection")

        features, errors = extract_features([event])

        self.assertEqual(errors, [])
        self.assertEqual(features[0]["is_connection"], 1)

    def test_timezone_normalization(self):
        event = make_event(
            timestamp="2026-11-21T14:30:00+05:30"
        )

        features, errors = extract_features([event])

        self.assertEqual(errors, [])
        self.assertEqual(features[0]["hour"], 9)

    def test_invalid_timestamp_is_skipped(self):
        event = make_event(timestamp="invalid_timestamp")

        features, errors = extract_features([event])

        self.assertEqual(features, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("invalid timestamp", errors[0].lower())

    def test_feature_schema_consistency(self):
        events = [
            make_event(event_id="EVT001", event_type="login_failed"),
            make_event(event_id="EVT002", event_type="login_success"),
            make_event(event_id="EVT003", event_type="process_execution"),
            make_event(event_id="EVT004", event_type="connection"),
            make_event(event_id="EVT005", event_type="unknown_event"),
        ]

        features, errors = extract_features(events)

        self.assertEqual(errors, [])
        self.assertEqual(len(features), 5)

        for feature_row in features:
            self.assertEqual(list(feature_row.keys()), FEATURE_NAMES)

        self.assertEqual(features[1]["is_login_success"], 1)
        self.assertEqual(features[4]["is_other_event"], 1)


if __name__ == "__main__":
    unittest.main()