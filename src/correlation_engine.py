
from datetime import timedelta

from src.detection_engine import parse_timestamp


def correlate_alerts_with_events(
    alerts,
    events,
    window_minutes=15
):
    """
    Find process and network events associated with
    each detection alert.

    Correlation uses case ID, host, user, and a time window.
    """

    correlated_results = []

    for alert in alerts:
        alert_time = parse_timestamp(alert["success_at"])

        related_events = []

        for event in events:
            if event.event_id in alert["failed_event_ids"]:
                continue

            if event.event_id == alert["success_event_id"]:
                continue

            if event.case_id != alert["case_id"]:
                continue

            if event.host != alert["host"]:
                continue

            if event.user != alert["user"]:
                continue

            event_time = parse_timestamp(event.timestamp)

            time_difference = event_time - alert_time

            if not (
                timedelta(seconds=0)
                <= time_difference
                <= timedelta(minutes=window_minutes)
            ):
                continue

            if event.event_type in (
                "process_execution",
                "connection"
            ):
                related_events.append({
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp,
                    "host": event.host,
                    "user": event.user,
                    "process_name": event.process_name,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "raw_event": event.raw_event
                })

        correlated_results.append({
            "alert_rule": alert["rule_id"],
            "case_id": alert["case_id"],
            "success_event_id": alert["success_event_id"],
            "related_event_count": len(related_events),
            "related_events": related_events
        })

    return correlated_results
