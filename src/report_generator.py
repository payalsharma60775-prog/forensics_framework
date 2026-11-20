from datetime import datetime, timezone


def _safe_text(value):
    """Convert a value into safe, readable Markdown text."""
    if value is None:
        return "N/A"

    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("|", "\\|")

    return text


def _format_timestamp(timestamp):
    """Convert ISO timestamps to readable UTC format."""
    if not timestamp:
        return "N/A"

    try:
        normalized = timestamp

        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")

    except (ValueError, TypeError, AttributeError):
        return _safe_text(timestamp)


def generate_markdown_report(report):
    """
    Generate a human-readable Markdown investigation report
    from the framework's JSON report dictionary.
    """

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    case_id = _safe_text(report.get("case_id", "UNKNOWN"))

    evidence = report.get("evidence") or {}
    alerts = report.get("alerts") or []
    correlations = report.get("correlations") or []
    timeline_data = report.get("timeline") or {}
    timeline_events = timeline_data.get("events") or []
    ml_analysis = report.get("ml_analysis") or {}
    ml_results = ml_analysis.get("results") or []
    feature_data = report.get("feature_extraction") or {}

    anomaly_findings = [
        result for result in ml_results
        if result.get("is_anomaly") == 1
    ]

    lines = []

    # --------------------------------------------------
    # 1. Report header and case overview
    # --------------------------------------------------
    lines.extend([
        "# Digital Forensic Investigation Report",
        "",
        f"**Case ID:** {case_id}",
        "",
        "---",
        "",
        "## 1. Case Overview",
        "",
        f"- **Total events examined:** {report.get('total_events', 0)}",
        f"- **Rule-based alerts:** {len(alerts)}",
        f"- **Correlated event groups:** {len(correlations)}",
        f"- **Timeline events:** {len(timeline_events)}",
        f"- **ML anomalies flagged:** {len(anomaly_findings)}",
        "",
    ])

    # --------------------------------------------------
    # 2. Evidence details
    # --------------------------------------------------
    lines.extend([
        "## 2. Evidence Integrity Information",
        "",
        f"- **Evidence ID:** {_safe_text(evidence.get('evidence_id'))}",
        f"- **Source type:** {_safe_text(evidence.get('source_type'))}",
        f"- **File path:** {_safe_text(evidence.get('file_path'))}",
        f"- **Recorded timestamp:** {_safe_text(evidence.get('collected_at'))}",
        f"- **SHA-256:** `{_safe_text(evidence.get('sha256'))}`",
        "",
        "The SHA-256 value represents the hash calculated during this "
        "processing run. It can be compared with a separately recorded "
        "hash to check whether the file contents are consistent. "
        "It does not, by itself, establish authenticity or chain of custody.",
        "",
    ])

    # --------------------------------------------------
    # 3. Ingestion summary
    # --------------------------------------------------
    ingestion_errors = report.get("ingestion_errors") or []

    lines.extend([
        "## 3. Event Ingestion",
        "",
        f"- **Events loaded:** {report.get('total_events', 0)}",
        f"- **Ingestion errors:** {len(ingestion_errors)}",
        "",
    ])

    if ingestion_errors:
        lines.append("### Ingestion Errors")
        lines.append("")

        for error in ingestion_errors:
            lines.append(f"- {_safe_text(error)}")

        lines.append("")

    # --------------------------------------------------
    # 4. Rule-based findings
    # --------------------------------------------------
    lines.extend([
        "## 4. Rule-Based Detection Findings",
        "",
    ])

    if not alerts:
        lines.extend([
            "No rule-based alerts were generated for the processed events.",
            "",
        ])
    else:
        for index, alert in enumerate(alerts, start=1):
            lines.extend([
                f"### Alert {index}: {_safe_text(alert.get('rule_id'))}",
                "",
                f"- **Severity:** {_safe_text(alert.get('severity'))}",
                f"- **Case:** {_safe_text(alert.get('case_id'))}",
                f"- **User:** {_safe_text(alert.get('user'))}",
                f"- **Host:** {_safe_text(alert.get('host'))}",
                f"- **Source IP:** {_safe_text(alert.get('source_ip'))}",
                f"- **Failed attempts:** {_safe_text(alert.get('failed_attempt_count'))}",
                f"- **First failure:** {_format_timestamp(alert.get('first_failed_at'))}",
                f"- **Successful login:** {_format_timestamp(alert.get('success_at'))}",
                f"- **Successful event ID:** {_safe_text(alert.get('success_event_id'))}",
                "",
                f"**Description:** {_safe_text(alert.get('description'))}",
                "",
            ])

            failed_ids = alert.get("failed_event_ids") or []

            if failed_ids:
                lines.append(
                    "**Failed authentication event IDs:** "
                    + ", ".join(_safe_text(item) for item in failed_ids)
                )
                lines.append("")

    # --------------------------------------------------
    # 5. Correlation findings
    # --------------------------------------------------
    lines.extend([
        "## 5. Contextual Event Correlation",
        "",
    ])

    if not correlations:
        lines.extend([
            "No event correlations were generated.",
            "",
        ])
    else:
        for index, correlation in enumerate(correlations, start=1):
            related_events = correlation.get("related_events") or []

            lines.extend([
                f"### Correlation Group {index}",
                "",
                f"- **Alert rule:** {_safe_text(correlation.get('alert_rule'))}",
                f"- **Case ID:** {_safe_text(correlation.get('case_id'))}",
                f"- **Trigger event:** {_safe_text(correlation.get('success_event_id'))}",
                f"- **Related event count:** {correlation.get('related_event_count', len(related_events))}",
                "",
            ])

            if related_events:
                lines.extend([
                    "| Event ID | Event type | Timestamp | Host | User | Process | Destination IP |",
                    "|---|---|---|---|---|---|",
                ])

                for event in related_events:
                    lines.append(
                        "| "
                        + " | ".join([
                            _safe_text(event.get("event_id")),
                            _safe_text(event.get("event_type")),
                            _format_timestamp(event.get("timestamp")),
                            _safe_text(event.get("host")),
                            _safe_text(event.get("user")),
                            _safe_text(event.get("process_name")),
                            _safe_text(event.get("destination_ip")),
                        ])
                        + " |"
                    )

                lines.append("")

    # --------------------------------------------------
    # 6. Timeline
    # --------------------------------------------------
    lines.extend([
        "## 6. Chronological Event Timeline",
        "",
    ])

    if not timeline_events:
        lines.extend([
            "No timeline events are available.",
            "",
        ])
    else:
        lines.extend([
            "| Timestamp (UTC) | Event ID | Event type | User | Host | Process | Source IP | Destination IP |",
            "|---|---|---|---|---|---|---|",
        ])

        for event in timeline_events:
            lines.append(
                "| "
                + " | ".join([
                    _format_timestamp(event.get("timestamp")),
                    _safe_text(event.get("event_id")),
                    _safe_text(event.get("event_type")),
                    _safe_text(event.get("user")),
                    _safe_text(event.get("host")),
                    _safe_text(event.get("process_name")),
                    _safe_text(event.get("source_ip")),
                    _safe_text(event.get("destination_ip")),
                ])
                + " |"
            )

        lines.append("")

    timeline_errors = timeline_data.get("processing_errors") or []

    if timeline_errors:
        lines.extend([
            "### Timeline Processing Errors",
            "",
        ])

        for error in timeline_errors:
            lines.append(f"- {_safe_text(error)}")

        lines.append("")

    # --------------------------------------------------
    # 7. ML findings
    # --------------------------------------------------
    lines.extend([
        "## 7. Machine Learning Anomaly Analysis",
        "",
        f"- **Algorithm:** {_safe_text(ml_analysis.get('algorithm'))}",
        f"- **Events analyzed:** {ml_analysis.get('total_events_analyzed', 0)}",
        f"- **Anomalies flagged:** {len(anomaly_findings)}",
        f"- **Feature count:** {feature_data.get('feature_count', 0)}",
        "",
    ])

    if anomaly_findings:
        lines.extend([
            "| Event ID | Classification | Anomaly score |",
            "|---|---|---|",
        ])

        for finding in anomaly_findings:
            lines.append(
                "| "
                + " | ".join([
                    _safe_text(finding.get("event_id")),
                    _safe_text(finding.get("classification")),
                    _safe_text(finding.get("anomaly_score")),
                ])
                + " |"
            )

        lines.append("")
    else:
        lines.extend([
            "No events were flagged as anomalies in this analysis.",
            "",
        ])

    ml_errors = ml_analysis.get("processing_errors") or []

    if ml_errors:
        lines.extend([
            "### ML Processing Errors",
            "",
        ])

        for error in ml_errors:
            lines.append(f"- {_safe_text(error)}")

        lines.append("")

    feature_errors = feature_data.get("feature_errors") or []

    if feature_errors:
        lines.extend([
            "### Feature Extraction Errors",
            "",
        ])

        for error in feature_errors:
            lines.append(f"- {_safe_text(error)}")

        lines.append("")

    # --------------------------------------------------
    # 8. Automated summary
    # --------------------------------------------------
    lines.extend([
        "## 8. Investigation Summary",
        "",
    ])

    if alerts:
        lines.append(
            f"The system generated {len(alerts)} rule-based alert(s) "
            "during analysis."
        )
    else:
        lines.append(
            "The system did not generate rule-based alerts during analysis."
        )

    if correlations:
        total_related = sum(
            correlation.get("related_event_count", 0)
            for correlation in correlations
        )

        lines.append(
            f"{total_related} event(s) were associated with alert "
            "context through the correlation engine."
        )

    if anomaly_findings:
        flagged_ids = ", ".join(
            _safe_text(item.get("event_id"))
            for item in anomaly_findings
        )

        lines.append(
            f"The Isolation Forest model flagged {len(anomaly_findings)} "
            f"event(s) for further review: {flagged_ids}."
        )
    else:
        lines.append(
            "The anomaly detection model did not flag events in this run."
        )

    lines.extend([
        "",
        "These findings represent automated analysis outputs and should "
        "be reviewed alongside original evidence and other investigative "
        "information.",
        "",
    ])

    # --------------------------------------------------
    # 9. Limitations
    # --------------------------------------------------
    lines.extend([
        "## 9. Limitations and Interpretation",
        "",
        "- A rule-based alert indicates that a configured detection pattern was observed; it is not proof of compromise.",
        "- Correlated events provide contextual association and do not establish causality.",
        "- Isolation Forest anomaly scores are relative model outputs, not attack probabilities.",
        "- An anomaly is not necessarily malicious, and normal classification does not guarantee benign activity.",
        "- Model performance has not been established by this report. Accuracy, precision, recall, F1-score, false-positive rate, and false-negative rate require evaluation against labeled ground-truth data.",
        "- SHA-256 hashing provides a content-integrity comparison, but does not independently establish evidence authenticity or chain of custody.",
        "",
        "---",
        "",
        "*End of report.*",
        "",
    ])

    return "\n".join(lines)