import unittest

from src.report_generator import generate_markdown_report


class TestReportGenerator(unittest.TestCase):

    def test_rejects_non_dictionary_input(self):
        with self.assertRaises(TypeError):
            generate_markdown_report([])

    def test_generates_report_for_empty_data(self):
        report = generate_markdown_report({})

        self.assertIn("# Digital Forensic Investigation Report", report)
        self.assertIn("UNKNOWN", report)
        self.assertIn("Limitations and Interpretation", report)

    def test_includes_case_and_evidence_details(self):
        data = {
            "case_id": "CASE001",
            "total_events": 8,
            "evidence": {
                "evidence_id": "EVD001",
                "source_type": "csv_event_log",
                "file_path": "data/raw/sample_events.csv",
                "collected_at": "2026-11-20T16:27:16+00:00",
                "sha256": "a" * 64,
            },
        }

        report = generate_markdown_report(data)

        self.assertIn("CASE001", report)
        self.assertIn("EVD001", report)
        self.assertIn("csv_event_log", report)
        self.assertIn("SHA-256", report)

    def test_includes_rule_based_alert(self):
        data = {
            "case_id": "CASE001",
            "total_events": 5,
            "total_alerts": 1,
            "alerts": [
                {
                    "rule_id": "AUTH-001",
                    "severity": "HIGH",
                    "case_id": "CASE001",
                    "user": "admin",
                    "host": "HOST01",
                    "source_ip": "192.168.1.10",
                    "failed_attempt_count": 3,
                    "failed_event_ids": ["EVT001", "EVT002"],
                    "success_event_id": "EVT003",
                    "first_failed_at": "2026-10-31T09:05:00",
                    "success_at": "2026-10-31T09:10:00",
                    "description": "Multiple failed logins followed by success.",
                }
            ],
        }

        report = generate_markdown_report(data)

        self.assertIn("AUTH-001", report)
        self.assertIn("HIGH", report)
        self.assertIn("admin", report)
        self.assertIn("EVT003", report)
        self.assertIn("Multiple failed logins", report)

    def test_includes_correlated_events(self):
        data = {
            "correlations": [
                {
                    "alert_rule": "AUTH-001",
                    "case_id": "CASE001",
                    "success_event_id": "EVT005",
                    "related_event_count": 1,
                    "related_events": [
                        {
                            "event_id": "EVT006",
                            "event_type": "process_execution",
                            "timestamp": "2026-10-31T09:15:00",
                            "host": "HOST01",
                            "user": "admin",
                            "process_name": "powershell.exe",
                            "destination_ip": None,
                        }
                    ],
                }
            ]
        }

        report = generate_markdown_report(data)

        self.assertIn("Contextual Event Correlation", report)
        self.assertIn("EVT006", report)
        self.assertIn("powershell.exe", report)

    def test_includes_timeline_events(self):
        data = {
            "timeline": {
                "total_events": 1,
                "processing_errors": [],
                "events": [
                    {
                        "event_id": "EVT001",
                        "timestamp": "2026-10-31T09:00:00+00:00",
                        "event_type": "login_success",
                        "user": "payal",
                        "host": "HOST01",
                        "process_name": None,
                        "source_ip": "192.168.1.5",
                        "destination_ip": None,
                    }
                ],
            }
        }

        report = generate_markdown_report(data)

        self.assertIn("Chronological Event Timeline", report)
        self.assertIn("EVT001", report)
        self.assertIn("login_success", report)
        self.assertIn("2026-10-31 09:00:00 UTC", report)

    def test_includes_ml_anomalies(self):
        data = {
            "feature_extraction": {
                "feature_count": 13,
                "feature_errors": [],
            },
            "ml_analysis": {
                "algorithm": "IsolationForest",
                "total_events_analyzed": 8,
                "anomaly_count": 1,
                "processing_errors": [],
                "results": [
                    {
                        "event_id": "EVT006",
                        "is_anomaly": 1,
                        "classification": "anomaly",
                        "anomaly_score": 0.206828,
                    },
                    {
                        "event_id": "EVT001",
                        "is_anomaly": 0,
                        "classification": "normal",
                        "anomaly_score": -0.047162,
                    },
                ],
            },
        }

        report = generate_markdown_report(data)

        self.assertIn("IsolationForest", report)
        self.assertIn("EVT006", report)
        self.assertIn("0.206828", report)
        self.assertIn("13", report)
        self.assertIn("not attack probabilities", report)

    def test_handles_missing_optional_sections(self):
        data = {
            "case_id": "CASE002",
            "alerts": [],
            "correlations": [],
            "timeline": {},
            "ml_analysis": {},
        }

        report = generate_markdown_report(data)

        self.assertIn("CASE002", report)
        self.assertIn("No rule-based alerts", report)
        self.assertIn("No event correlations", report)
        self.assertIn("No timeline events", report)
        self.assertIn("No events were flagged", report)

    def test_escapes_table_pipe_characters(self):
        data = {
            "timeline": {
                "events": [
                    {
                        "event_id": "EVT001",
                        "timestamp": "2026-10-31T09:00:00",
                        "event_type": "login|success",
                        "user": "user|admin",
                        "host": "HOST01",
                    }
                ]
            }
        }

        report = generate_markdown_report(data)

        self.assertIn(r"login\|success", report)
        self.assertIn(r"user\|admin", report)

    def test_invalid_timestamps_are_preserved_readably(self):
        data = {
            "timeline": {
                "events": [
                    {
                        "event_id": "EVT001",
                        "timestamp": "invalid-time",
                        "event_type": "connection",
                        "user": "admin",
                        "host": "HOST01",
                    }
                ]
            }
        }

        report = generate_markdown_report(data)

        self.assertIn("invalid-time", report)
        self.assertIn("EVT001", report)


if __name__ == "__main__":
    unittest.main()