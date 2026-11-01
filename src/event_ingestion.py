
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.event_schema import SecurityEvent


REQUIRED_FIELDS = [
    "event_id",
    "case_id",
    "timestamp",
    "source_type",
    "event_type",
]

OPTIONAL_FIELDS = [
    "host",
    "user",
    "process_name",
    "source_ip",
    "destination_ip",
    "raw_event",
]


def load_events_from_csv(
    csv_path: str,
    expected_case_id: Optional[str] = None
) -> tuple[list[SecurityEvent], list[str]]:

    path = Path(csv_path)

    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    events = []
    errors = []
    seen_event_ids = set()

    with path.open("r", encoding="utf-8-sig") as file:
        non_empty_lines = (line for line in file if line.strip())
        reader = csv.DictReader(non_empty_lines)

        if reader.fieldnames is None:
            raise ValueError("CSV file is empty or has no header.")

        reader.fieldnames = [
            field.strip() for field in reader.fieldnames
        ]

        missing_fields = [
            field for field in REQUIRED_FIELDS
            if field not in reader.fieldnames
        ]

        if missing_fields:
            raise ValueError(
                f"Missing required CSV columns: {missing_fields}"
            )

        for row_number, row in enumerate(reader, start=2):
            try:
                values = {
                    field: (row.get(field) or "").strip()
                    for field in REQUIRED_FIELDS
                }

                for field, value in values.items():
                    if not value:
                        raise ValueError(
                            f"Required field '{field}' is empty"
                        )

                timestamp = values["timestamp"].replace(
                    "Z", "+00:00"
                )
                datetime.fromisoformat(timestamp)

                if expected_case_id and (
                    values["case_id"] != expected_case_id
                ):
                    raise ValueError("Unexpected case_id")

                event_id = values["event_id"]

                if event_id in seen_event_ids:
                    raise ValueError(
                        f"Duplicate event_id: {event_id}"
                    )

                optional_values = {
                    field: (row.get(field) or "").strip() or None
                    for field in OPTIONAL_FIELDS
                }

                event = SecurityEvent(
                    event_id=event_id,
                    case_id=values["case_id"],
                    timestamp=values["timestamp"],
                    source_type=values["source_type"],
                    event_type=values["event_type"],
                    **optional_values
                )

                events.append(event)
                seen_event_ids.add(event_id)

            except (ValueError, TypeError) as exc:
                errors.append(f"Row {row_number}: {exc}")

    return events, errors

