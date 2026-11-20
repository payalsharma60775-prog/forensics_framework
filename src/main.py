
import json
from pathlib import Path

from src.event_ingestion import load_events_from_csv
from src.detection_engine import (
    detect_brute_force_followed_by_success
)
from src.correlation_engine import correlate_alerts_with_events
from src.feature_extraction import extract_features
from src.anomaly_detection import detect_anomalies
from src.timeline_engine import build_event_timeline
from src.report_generator import generate_markdown_report

from src.evidence_schema import (
    EvidenceRecord,
    calculate_sha256,
    current_utc_timestamp
)


def run_investigation():
    case_id = "CASE001"
    dataset_path = "data/raw/sample_events.csv"

    print("=" * 60)
    print(" AI-AUGMENTED DIGITAL FORENSICS FRAMEWORK")
    print("=" * 60)

    # STEP 1: Verify evidence integrity
    print("\n[1] Calculating evidence hash...")

    evidence_hash = calculate_sha256(dataset_path)

    evidence = EvidenceRecord(
        evidence_id="EVD001",
        case_id=case_id,
        source_type="csv_event_log",
        file_path=dataset_path,
        collected_at=current_utc_timestamp(),
        sha256=evidence_hash
    )

    print(f"Evidence ID: {evidence.evidence_id}")
    print(f"SHA-256: {evidence.sha256}")

    # STEP 2: Event ingestion
    print("\n[2] Loading security events...")

    events, errors = load_events_from_csv(
        dataset_path,
        expected_case_id=case_id
    )

    print(f"Events loaded: {len(events)}")
    print(f"Invalid records: {len(errors)}")

    if errors:
        print("\nIngestion errors:")
        for error in errors:
            print("-", error)

    # STEP 3: Rule-based threat detection
    print("\n[3] Running rule-based threat detection...")

    alerts = detect_brute_force_followed_by_success(events)

    print(f"Rule-based alerts generated: {len(alerts)}")

    # STEP 4: Contextual event correlation
    print("\n[4] Correlating related events...")

    correlations = correlate_alerts_with_events(
        alerts,
        events
    )

    for result in correlations:
        print(f"\nAlert: {result['alert_rule']}")
        print(f"Related events: {result['related_event_count']}")

        for event in result["related_events"]:
            print(
                f"- {event['event_id']}: "
                f"{event['event_type']} | "
                f"{event['timestamp']}"
            )

    # STEP 5: Timeline reconstruction
    print("\n[5] Reconstructing chronological timeline...")

    timeline, timeline_errors = build_event_timeline(events)

    print(f"Timeline events generated: {len(timeline)}")
    print(f"Timeline errors: {len(timeline_errors)}")

    if timeline_errors:
        for error in timeline_errors:
            print("-", error)

    print("\n--- INVESTIGATION TIMELINE (UTC) ---")

    for entry in timeline:
        print(
            f"{entry['timestamp']} | "
            f"{entry['event_id']} | "
            f"{entry['event_type']} | "
            f"User: {entry['user']} | "
            f"Host: {entry['host']} | "
            f"Process: {entry['process_name']}"
        )

    # STEP 6: ML feature extraction
    print("\n[6] Extracting ML features...")

    feature_rows, feature_errors = extract_features(events)

    print(f"Feature rows generated: {len(feature_rows)}")
    print(f"Feature extraction errors: {len(feature_errors)}")

    if feature_errors:
        for error in feature_errors:
            print("-", error)

    # STEP 7: ML anomaly detection
    print("\n[7] Running Isolation Forest anomaly detection...")

    anomalies, anomaly_errors = detect_anomalies(
        events,
        feature_rows
    )

    print(f"ML results generated: {len(anomalies)}")
    print(f"ML processing errors: {len(anomaly_errors)}")

    if anomaly_errors:
        for error in anomaly_errors:
            print("-", error)

    anomaly_findings = [
        result for result in anomalies
        if result["is_anomaly"] == 1
    ]

    print(f"Anomalies identified: {len(anomaly_findings)}")

    for finding in anomaly_findings:
        print(
            f"- Event: {finding['event_id']} | "
            f"Score: {finding['anomaly_score']}"
        )

    # STEP 8: Assemble structured investigation report
    report = {
        "case_id": case_id,
        "evidence": {
            "evidence_id": evidence.evidence_id,
            "source_type": evidence.source_type,
            "file_path": evidence.file_path,
            "collected_at": evidence.collected_at,
            "sha256": evidence.sha256
        },
        "total_events": len(events),
        "ingestion_errors": errors,
        "total_alerts": len(alerts),
        "alerts": alerts,
        "correlations": correlations,
        "timeline": {
            "total_events": len(timeline),
            "processing_errors": timeline_errors,
            "events": timeline
        },
        "feature_extraction": {
            "feature_count": (
                len(feature_rows[0])
                if feature_rows else 0
            ),
            "feature_errors": feature_errors
        },
        "ml_analysis": {
            "algorithm": "IsolationForest",
            "total_events_analyzed": len(anomalies),
            "anomaly_count": len(anomaly_findings),
            "processing_errors": anomaly_errors,
            "results": anomalies
        }
    }

    # STEP 9: Save JSON report
    print("\n[8] Generating structured JSON report...")

    output_dir = Path("data/processed")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "investigation_report.json"

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"JSON report saved: {json_path}")

    # STEP 10: Generate human-readable Markdown report
    print("\n[9] Generating human-readable investigation report...")

    markdown_report = generate_markdown_report(report)

    markdown_path = output_dir / "investigation_report.md"

    with markdown_path.open("w", encoding="utf-8") as file:
        file.write(markdown_report)

    print(f"Markdown report saved: {markdown_path}")

    print("\nInvestigation completed successfully.")


if __name__ == "__main__":
    run_investigation()