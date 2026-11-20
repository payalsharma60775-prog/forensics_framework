
import json
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


def _is_valid_timestamp(value: str):
    """Validate an ISO 8601 timestamp."""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def load_events_from_jsonl(
    jsonl_path,
    expected_case_id: Optional[str] = None,
    column_mapping: Optional[dict] = None,
):
    """Load JSONL events, preserving valid records when individual lines fail."""
    path = Path(jsonl_path)

    if not path.exists():
        return [], [f"JSONL file not found: {path}"]

    if not path.is_file():
        return [], [f"JSONL path is not a file: {path}"]

    try:
        file = path.open("r", encoding="utf-8-sig")
    except OSError as error:
        return [], [f"Could not read JSONL file: {error}"]

    mapping = {field: field for field in ALL_FIELDS}

    if column_mapping is not None:
        if not isinstance(column_mapping, dict):
            file.close()
            return [], ["Column mapping must be a dictionary."]

        for framework_field, json_field in column_mapping.items():
            if framework_field not in ALL_FIELDS:
                file.close()
                return [], [
                    f"Unsupported framework field in mapping: {framework_field}"
                ]

            if not isinstance(json_field, str) or not json_field.strip():
                file.close()
                return [], [
                    f"Invalid JSONL field mapping for {framework_field}."
                ]

            mapping[framework_field] = json_field.strip()

    mapped_fields = list(mapping.values())

    if len(mapped_fields) != len(set(mapped_fields)):
        file.close()
        return [], [
            "Multiple framework fields cannot map to the same JSONL field."
        ]

    events = []
    errors = []
    seen_event_ids = set()

    with file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                errors.append(
                    f"Line {line_number}: invalid JSON "
                    f"at column {error.colno}: {error.msg}."
                )
                continue

            if not isinstance(record, dict):
                errors.append(
                    f"Line {line_number}: expected a JSON object."
                )
                continue

            values = {}
            invalid_record = False

            for field in ALL_FIELDS:
                json_field = mapping[field]
                value = record.get(json_field)

                if field in REQUIRED_FIELDS:
                    if value is None or str(value).strip() == "":
                        errors.append(
                            f"Line {line_number}: missing required value "
                            f"for '{field}' (JSON key: '{json_field}')."
                        )
                        invalid_record = True
                        break

                    if isinstance(value, (dict, list, bool)):
                        errors.append(
                            f"Line {line_number}: invalid value type "
                            f"for '{field}'."
                        )
                        invalid_record = True
                        break

                    values[field] = str(value).strip()

                else:
                    if value is None:
                        values[field] = None
                    elif isinstance(value, (dict, list)):
                        values[field] = json.dumps(
                            value, ensure_ascii=False
                        )
                    else:
                        values[field] = str(value).strip()

            if invalid_record:
                continue

            event_id = values["event_id"]
            case_id = values["case_id"]
            timestamp = values["timestamp"]

            if not _is_valid_timestamp(timestamp):
                errors.append(
                    f"Line {line_number}: invalid ISO timestamp "
                    f"'{timestamp}'."
                )
                continue

            if expected_case_id and case_id != expected_case_id:
                errors.append(
                    f"Line {line_number}: case ID '{case_id}' does not "
                    f"match expected case '{expected_case_id}'."
                )
                continue

            if event_id in seen_event_ids:
                errors.append(
                    f"Line {line_number}: duplicate event ID '{event_id}'."
                )
                continue

            seen_event_ids.add(event_id)

            if not values["raw_event"]:
                values["raw_event"] = json.dumps(
                    record, ensure_ascii=False
                )

            events.append(SecurityEvent(**values))

    return events, errors
