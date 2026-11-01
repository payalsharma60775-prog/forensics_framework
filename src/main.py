

import json
from pathlib import Path

from src.event_ingestion import load_events_from_csv
from src.detection_engine import (
    detect_brute_force_followed_by_success
)
from src.correlation_engine import correlate_alerts_with_events

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

    # STEP 3: Threat detection
    print("\n[3] Running threat detection...")

    alerts = detect_brute_force_followed_by_success(events)

    print(f"Alerts generated: {len(alerts)}")

    # STEP 4: Event correlation
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

    # STEP 5: Generate investigation report
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
        "correlations": correlations
    }

    output_path = Path(
        "data/processed/investigation_report.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n[5] Investigation report generated.")
    print(f"Report location: {output_path}")
    print("\nInvestigation completed.")


if __name__ == "__main__":
    run_investigation()


