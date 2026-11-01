
from datetime import datetime, timezone


def parse_timestamp(timestamp: str) -> datetime:
    """Convert timestamps into comparable UTC datetime objects."""
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def detect_brute_force_followed_by_success(
    events,
    failure_threshold=3,
    window_minutes=10
):
    """
    Detect repeated failed logins followed by a successful login
    from the same IP, host, and user within a time window.
    """

    alerts = []

    failed_events = [
        event for event in events
        if event.event_type == "login_failed"
        and event.source_ip
    ]

    successful_events = [
        event for event in events
        if event.event_type == "login_success"
        and event.source_ip
    ]

    for success in successful_events:
        success_time = parse_timestamp(success.timestamp)

        matching_failures = []

        for failure in failed_events:
            same_identity = (
                failure.case_id == success.case_id
                and failure.source_ip == success.source_ip
                and failure.host == success.host
                and failure.user == success.user
            )

            if not same_identity:
                continue

            failure_time = parse_timestamp(failure.timestamp)

            time_difference = success_time - failure_time

            if (
                0 <= time_difference.total_seconds()
                <= window_minutes * 60
            ):
                matching_failures.append(failure)

        if len(matching_failures) >= failure_threshold:
            matching_failures.sort(
                key=lambda event: parse_timestamp(event.timestamp)
            )

            alerts.append({
                "rule_id": "AUTH-001",
                "severity": "HIGH",
                "case_id": success.case_id,
                "source_ip": success.source_ip,
                "host": success.host,
                "user": success.user,
                "failed_attempt_count": len(matching_failures),
                "failed_event_ids": [
                    event.event_id for event in matching_failures
                ],
                "success_event_id": success.event_id,
                "first_failed_at": matching_failures[0].timestamp,
                "success_at": success.timestamp,
                "description": (
                    "Multiple failed login attempts were followed "
                    "by a successful login from the same source."
                )
            })

    return alerts
