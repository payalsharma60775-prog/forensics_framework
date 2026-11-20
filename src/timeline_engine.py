from datetime import datetime, timezone


def _parse_timestamp(timestamp):
    """
    Parse an ISO-8601 timestamp and normalize it to UTC.

    Naive timestamps are treated as UTC to remain consistent
    with the project's existing timestamp-handling convention.
    """
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("Timestamp must be a non-empty string.")

    normalized_timestamp = timestamp.strip()

    if normalized_timestamp.endswith("Z"):
        normalized_timestamp = normalized_timestamp[:-1] + "+00:00"

    parsed = datetime.fromisoformat(normalized_timestamp)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def build_event_timeline(events):
    """
    Build a chronological timeline from SecurityEvent objects.

    Returns:
        (timeline, errors)

    Timeline entries are sorted chronologically in UTC.
    Events with invalid timestamps are skipped and reported.
    """
    timeline = []
    errors = []

    for event in events:
        event_id = getattr(event, "event_id", "UNKNOWN")

        try:
            parsed_timestamp = _parse_timestamp(event.timestamp)

            timeline_entry = {
                "event_id": event.event_id,
                "case_id": event.case_id,
                "timestamp": parsed_timestamp.isoformat(),
                "event_type": event.event_type,
                "source_type": event.source_type,
                "host": event.host,
                "user": event.user,
                "process_name": event.process_name,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "raw_event": event.raw_event,
            }

            timeline.append((parsed_timestamp, timeline_entry))

        except (ValueError, TypeError, AttributeError) as exc:
            errors.append(
                f"Event {event_id}: unable to add to timeline - {exc}"
            )

    # Sort by timestamp, with event ID as a deterministic tie-breaker.
    timeline.sort(
        key=lambda item: (
            item[0],
            item[1]["event_id"]
        )
    )

    # Return the entries without the internal datetime sorting key.
    sorted_timeline = [
        entry for _, entry in timeline
    ]

    return sorted_timeline, errors