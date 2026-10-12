
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import hashlib


@dataclass
class InvestigationCase:
    case_id: str
    case_name: str
    description: str = ""

    def __post_init__(self):
        if not self.case_id.strip():
            raise ValueError("case_id must not be empty")
        if not self.case_name.strip():
            raise ValueError("case_name must not be empty")


@dataclass
class EvidenceRecord:
    evidence_id: str
    case_id: str
    source_type: str
    file_path: str
    collected_at: str
    sha256: Optional[str] = None

    def __post_init__(self):
        fields = {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "source_type": self.source_type,
            "file_path": self.file_path,
            "collected_at": self.collected_at,
        }

        for name, value in fields.items():
            if not value or not value.strip():
                raise ValueError(f"{name} must not be empty")

        if self.sha256 is not None:
            if len(self.sha256) != 64:
                raise ValueError("sha256 must contain 64 hexadecimal characters")
            try:
                int(self.sha256, 16)
            except ValueError as exc:
                raise ValueError("sha256 must be hexadecimal") from exc


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 for the current contents of a file."""
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def current_utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()