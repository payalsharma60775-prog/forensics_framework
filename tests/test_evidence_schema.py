import hashlib
import tempfile

from src.evidence_schema import calculate_sha256

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


    def test_sha256_matches_expected_hash(self):
        content = b"sample forensic evidence"

        with tempfile.NamedTemporaryFile(delete=False) as sample:
            sample.write(content)
            sample_path = sample.name

        try:
            expected_hash = hashlib.sha256(content).hexdigest()
            actual_hash = calculate_sha256(sample_path)
            self.assertEqual(actual_hash, expected_hash)
        finally:
            import os
            os.remove(sample_path)

    def test_sha256_changes_when_file_content_changes(self):
        with tempfile.NamedTemporaryFile(delete=False) as sample:
            sample.write(b"original evidence")
            sample_path = sample.name

        try:
            original_hash = calculate_sha256(sample_path)

            with open(sample_path, "wb") as sample:
                sample.write(b"modified evidence")

            modified_hash = calculate_sha256(sample_path)
            self.assertNotEqual(original_hash, modified_hash)
        finally:
            import os
            os.remove(sample_path)

if __name__ == "__main__":
    unittest.main()