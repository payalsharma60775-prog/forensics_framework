

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

ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS


def get_csv_headers(csv_path: str) -> list[str]:
    """
    Read and return the column headers from a CSV dataset.
    Whitespace and UTF-8 BOM are handled.
    """
    path = Path(csv_path)

    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        non_empty_lines = (line for line in file if line.strip())
        reader = csv.reader(non_empty_lines)

        headers = next(reader, None)

    if not headers:
        raise ValueError("CSV file is empty or has no header.")

    headers = [header.strip() for header in headers]

    if any(not header for header in headers):
        raise ValueError("CSV contains an empty column name.")

    if len(headers) != len(set(headers)):
        raise ValueError("CSV contains duplicate column names.")

    return headers


def load_events_from_csv(
    csv_path: str,
    expected_case_id: Optional[str] = None,
    column_mapping: Optional[dict[str, str]] = None,
) -> tuple[list[SecurityEvent], list[str]]:
    """
    Load security events from a CSV dataset.

    column_mapping maps framework field names to uploaded CSV
    column names.

    Example:
        {
            "event_id": "Event ID",
            "case_id": "Investigation",
            "timestamp": "Date",
            "source_type": "Log Source",
            "event_type": "Activity",
            "user": "Username",
        }

    If no mapping is supplied, the original standard CSV format
    is used for backward compatibility.
    """

    path = Path(csv_path)

    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    events = []
    errors = []
    seen_event_ids = set()

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        non_empty_lines = (line for line in file if line.strip())
        reader = csv.DictReader(non_empty_lines)

        if reader.fieldnames is None:
            raise ValueError("CSV file is empty or has no header.")

        reader.fieldnames = [
            field.strip() for field in reader.fieldnames
        ]

        headers = reader.fieldnames

        if any(not header for header in headers):
            raise ValueError("CSV contains an empty column name.")

        if len(headers) != len(set(headers)):
            raise ValueError("CSV contains duplicate column names.")

        # Use the original standard names when no mapping is given.
        if column_mapping is None:
            mapping = {
                field: field
                for field in ALL_FIELDS
                if field in headers
            }
        else:
            mapping = column_mapping.copy()

        # Check that every required framework field is mapped.
        missing_mappings = [
            field for field in REQUIRED_FIELDS
            if not mapping.get(field)
        ]

        if missing_mappings:
            raise ValueError(
                f"Missing required column mappings: {missing_mappings}"
            )

        # Check that mapped CSV columns actually exist.
        for framework_field, csv_column in mapping.items():
            if framework_field not in ALL_FIELDS:
                raise ValueError(
                    f"Unknown framework field: {framework_field}"
                )

            if csv_column not in headers:
                raise ValueError(
                    f"Mapped CSV column '{csv_column}' "
                    f"for '{framework_field}' was not found."
                )

        for row_number, row in enumerate(reader, start=2):
            try:
                values = {}

                for field in REQUIRED_FIELDS:
                    csv_column = mapping[field]
                    value = (row.get(csv_column) or "").strip()

                    if not value:
                        raise ValueError(
                            f"Required field '{field}' is empty"
                        )

                    values[field] = value

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

                optional_values = {}

                for field in OPTIONAL_FIELDS:
                    csv_column = mapping.get(field)

                    if csv_column:
                        value = (row.get(csv_column) or "").strip()
                        optional_values[field] = value or None
                    else:
                        optional_values[field] = None

                event = SecurityEvent(
                    **values,
                    **optional_values,
                )

                events.append(event)
                seen_event_ids.add(event_id)

            except (ValueError, TypeError) as exc:
                errors.append(f"Row {row_number}: {exc}")

    return events, errors

