
import unittest

from src.event_schema import SecurityEvent


class TestSecurityEvent(unittest.TestCase):

    def test_valid_security_event(self):
        event = SecurityEvent(
            event_id="EVT-001",
            case_id="CASE-001",
            timestamp="2026-10-13T10:30:00Z",
            source_type="windows_event_log",
            event_type="process_execution",
            host="WORKSTATION-01",
            user="analyst_user",
            process_name="powershell.exe",
            source_ip="192.168.1.10",
            destination_ip="203.0.113.20",
            raw_event="Sample process execution event",
        )

        self.assertEqual(event.event_id, "EVT-001")
        self.assertEqual(event.case_id, "CASE-001")
        self.assertEqual(event.event_type, "process_execution")
        self.assertEqual(event.process_name, "powershell.exe")

    def test_optional_fields_can_be_omitted(self):
        event = SecurityEvent(
            event_id="EVT-002",
            case_id="CASE-001",
            timestamp="2026-10-13T10:35:00Z",
            source_type="windows_event_log",
            event_type="user_login",
        )

        self.assertIsNone(event.host)
        self.assertIsNone(event.user)
        self.assertIsNone(event.process_name)
        self.assertIsNone(event.source_ip)
        self.assertIsNone(event.destination_ip)
        self.assertIsNone(event.raw_event)


if __name__ == "__main__":
    unittest.main()