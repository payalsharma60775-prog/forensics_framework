
import unittest

from src.evidence_schema import InvestigationCase, EvidenceRecord


class TestEvidenceSchema(unittest.TestCase):

    def test_valid_case(self):
        case = InvestigationCase(
            case_id="CASE-001",
            case_name="Sample Investigation",
            description="Testing the case schema",
        )

        self.assertEqual(case.case_id, "CASE-001")
        self.assertEqual(case.case_name, "Sample Investigation")

    def test_valid_evidence_record(self):
        evidence = EvidenceRecord(
            evidence_id="EVD-001",
            case_id="CASE-001",
            source_type="system_log",
            file_path="data/raw/sample.log",
            collected_at="2026-10-11T12:00:00+00:00",
        )

        self.assertEqual(evidence.evidence_id, "EVD-001")
        self.assertEqual(evidence.case_id, "CASE-001")

    def test_empty_case_id_is_rejected(self):
        with self.assertRaises(ValueError):
            InvestigationCase(
                case_id="",
                case_name="Sample Investigation",
            )


if __name__ == "__main__":
    unittest.main()