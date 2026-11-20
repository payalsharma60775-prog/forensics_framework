
from datetime import datetime, timezone


FEATURE_NAMES = [
    "hour",
    "day_of_week",
    "is_weekend",
    "has_user",
    "has_host",
    "has_process",
    "has_source_ip",
    "has_destination_ip",
    "is_login_failed",
    "is_login_success",
    "is_process_execution",
    "is_connection",
    "is_other_event",
]


def _parse_timestamp(value):
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError, AttributeError):
        return None


def extract_features(events):
    """Extract numeric features from SecurityEvent objects.

    Returns:
        (feature_rows, errors)
    """
    feature_rows = []
    errors = []

    known_event_types = {
        "login_failed",
        "login_success",
        "process_execution",
        "connection",
    }

    for index, event in enumerate(events, start=1):
        timestamp = _parse_timestamp(event.timestamp)

        if timestamp is None:
            errors.append(
                f"Event {index} ({event.event_id}): invalid timestamp."
            )
            continue

        event_type = (event.event_type or "").strip().lower()

        features = {
            "hour": timestamp.hour,
            "day_of_week": timestamp.weekday(),
            "is_weekend": int(timestamp.weekday() >= 5),

            "has_user": int(bool(event.user)),
            "has_host": int(bool(event.host)),
            "has_process": int(bool(event.process_name)),
            "has_source_ip": int(bool(event.source_ip)),
            "has_destination_ip": int(bool(event.destination_ip)),

            "is_login_failed": int(event_type == "login_failed"),
            "is_login_success": int(event_type == "login_success"),
            "is_process_execution": int(
                event_type == "process_execution"
            ),
            "is_connection": int(event_type == "connection"),
            "is_other_event": int(
                event_type not in known_event_types
            ),
        }

        feature_rows.append(features)

    return feature_rows, errors
