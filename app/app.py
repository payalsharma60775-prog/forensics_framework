
import csv
import hashlib
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st

# ---------------------------------------------------------
# 1. PROJECT CONFIGURATION AND BACKEND IMPORTS
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.event_ingestion import (
    get_csv_headers,
    load_events_from_csv,
)
from src.detection_engine import detect_brute_force_followed_by_success
from src.correlation_engine import correlate_alerts_with_events
from src.feature_extraction import extract_features, FEATURE_NAMES
from src.anomaly_detection import detect_anomalies
from src.timeline_engine import build_event_timeline
from src.report_generator import generate_markdown_report
from src.pdf_report_generator import generate_pdf_report
from src.evidence_schema import (
    EvidenceRecord,
    calculate_sha256,
    current_utc_timestamp,
)

st.set_page_config(
    page_title="Forensic Insight | DFIR Console",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# 2. PROFESSIONAL DASHBOARD STYLING
# ---------------------------------------------------------

st.markdown("""
<style>
    :root {
        --navy: #101B2B;
        --panel: #17263A;
        --panel-light: #20334B;
        --teal: #25C4B5;
        --text: #E8EEF6;
        --muted: #A6B5C8;
    }

    .stApp {
        background: #0B1421;
        color: var(--text);
    }

    [data-testid="stSidebar"] {
        background: #101B2B;
        border-right: 1px solid #263950;
    }

    [data-testid="stSidebar"] * {
        color: #E8EEF6;
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    h1, h2, h3 {
        color: #F1F5FA !important;
    }

    p, label, .stMarkdown {
        color: #D1DBE8;
    }

    .hero {
        background: linear-gradient(115deg, #172B42, #102C38);
        border: 1px solid #285064;
        border-radius: 16px;
        padding: 25px 28px;
        margin-bottom: 22px;
    }

    .hero-title {
        color: #F4F8FC;
        font-size: 30px;
        font-weight: 750;
        letter-spacing: 0.5px;
        margin: 0;
    }

    .hero-subtitle {
        color: #AFC4D7;
        font-size: 14px;
        margin-top: 7px;
    }

    .section-label {
        color: #25C4B5;
        font-size: 12px;
        font-weight: 750;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-bottom: 7px;
    }

    .panel {
        background: #17263A;
        border: 1px solid #293D54;
        border-radius: 13px;
        padding: 17px 19px;
        margin-bottom: 12px;
    }

    .panel-title {
        color: #F1F5FA;
        font-size: 16px;
        font-weight: 700;
        margin-bottom: 8px;
    }

    .panel-text {
        color: #AFC0D2;
        font-size: 13px;
    }

    .metric-card {
        background: #17263A;
        border: 1px solid #293D54;
        border-radius: 13px;
        padding: 17px;
        min-height: 105px;
    }

    .metric-label {
        color: #AFC0D2;
        font-size: 12px;
        font-weight: 600;
    }

    .metric-value {
        color: #F4F8FC;
        font-size: 29px;
        font-weight: 750;
        margin-top: 8px;
    }

    .alert-card {
        background: #241F2A;
        border: 1px solid #80504E;
        border-left: 5px solid #F07869;
        border-radius: 12px;
        padding: 17px;
        margin: 10px 0;
    }

    .event-card {
        background: #17263A;
        border: 1px solid #293D54;
        border-radius: 10px;
        padding: 13px 16px;
        margin: 8px 0;
    }

    .hash-box {
        background: #101B2B;
        border: 1px solid #31506B;
        border-radius: 9px;
        padding: 13px;
        color: #66D9CE;
        font-family: monospace;
        overflow-wrap: anywhere;
    }

    div.stButton > button {
        background: #167F82;
        color: white;
        border: 1px solid #25C4B5;
        border-radius: 9px;
        font-weight: 700;
        min-height: 43px;
    }

    div.stButton > button:hover {
        background: #1A9995;
        color: white;
        border-color: #58E0D2;
    }

    div[data-testid="stDownloadButton"] button {
        background: #203B52;
        color: white;
        border: 1px solid #3B6680;
        border-radius: 9px;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #293D54;
        border-radius: 10px;
    }

    .stTabs [data-baseweb="tab"] {
        color: #B8C9D9;
        font-weight: 650;
    }

    .stTabs [aria-selected="true"] {
        color: #38D6C7 !important;
    }

    hr {
        border-color: #293D54;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# 3. HELPER FUNCTIONS
# ---------------------------------------------------------

UNMAPPED = "-- Not mapped --"

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

FIELD_LABELS = {
    "event_id": "Event ID",
    "case_id": "Case ID",
    "timestamp": "Timestamp",
    "source_type": "Log Source",
    "event_type": "Event Type",
    "host": "Host / Device",
    "user": "User",
    "process_name": "Process Name",
    "source_ip": "Source IP",
    "destination_ip": "Destination IP",
    "raw_event": "Raw Event Description",
}


def suggest_column(field, headers):
    """Suggest a CSV header based on common field names."""

    aliases = {
        "event_id": ["event_id", "event id", "id", "record_id"],
        "case_id": ["case_id", "case id", "investigation", "case"],
        "timestamp": ["timestamp", "time", "date", "datetime"],
        "source_type": ["source_type", "source type", "log source", "source"],
        "event_type": ["event_type", "event type", "activity", "action"],
        "host": ["host", "hostname", "computer", "device"],
        "user": ["user", "username", "account", "user_name"],
        "process_name": ["process_name", "process name", "process"],
        "source_ip": ["source_ip", "source ip", "src_ip", "src"],
        "destination_ip": [
            "destination_ip", "destination ip", "dest_ip", "dst_ip"
        ],
        "raw_event": ["raw_event", "raw event", "description", "message"],
    }

    normalized = {
        str(header).strip().lower(): header for header in headers
    }

    for alias in aliases.get(field, []):
        if alias.lower() in normalized:
            return normalized[alias.lower()]

    return UNMAPPED


def safe_filename(name):
    """Remove unsafe characters from an uploaded filename."""

    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).name)


def save_uploaded_evidence(uploaded_file):
    """Save uploads under a content-hash-based filename."""

    content = uploaded_file.getvalue()
    digest = hashlib.sha256(content).hexdigest()

    upload_folder = PROJECT_ROOT / "data" / "raw" / "uploads"
    upload_folder.mkdir(parents=True, exist_ok=True)

    filename = safe_filename(uploaded_file.name)
    destination = upload_folder / f"{digest[:12]}_{filename}"

    if not destination.exists():
        destination.write_bytes(content)

    return destination, digest


def metric_card(label, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_related_count(correlations):
    return sum(
        item.get("related_event_count", 0)
        for item in correlations
    )


# ---------------------------------------------------------
# 4. SIDEBAR
# ---------------------------------------------------------

with st.sidebar:
    st.markdown("## 🔎 FORENSIC INSIGHT")
    st.caption("DIGITAL FORENSICS & INCIDENT RESPONSE")
    st.divider()

    st.markdown("### Investigation Workspace")

    case_id = st.text_input(
        "Investigation Case ID",
        value="CASE001",
        help="Enter the case identifier associated with the evidence.",
    )

    st.markdown("---")
    st.markdown("### Investigation Modules")

    st.markdown("""
    - Evidence Management
    - Event Ingestion
    - Integrity Verification
    - Threat Detection
    - Event Correlation
    - Forensic Timeline
    - Investigation Reporting
    """)

    st.divider()
    st.caption("Minor Project Prototype")
    st.caption("AI-Augmented Digital Forensics Framework")
    st.caption("Version 1.0")


# ---------------------------------------------------------
# 5. MAIN HEADER
# ---------------------------------------------------------

st.markdown("""
<div class="hero">
    <div class="section-label">Digital Forensics and Incident Response</div>
    <div class="hero-title">Forensic Insight</div>
    <div class="hero-subtitle">
        AI-Augmented Digital Forensics and Threat Correlation Framework
        <br>
        Evidence integrity · Security-event analysis · Threat detection · Correlation
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# 6. DATA UPLOAD AND COLUMN MAPPING
# ---------------------------------------------------------

st.markdown('<div class="section-label">01 / Evidence Ingestion</div>',
            unsafe_allow_html=True)
st.subheader("Upload and Prepare Evidence")

uploaded_file = st.file_uploader(
    "Select a security event CSV file",
    type=["csv"],
    help="Upload a CSV containing security or forensic event records.",
)

dataset_path = None
uploaded_headers = []
upload_digest = None

if uploaded_file is not None:
    try:
        dataset_path, upload_digest = save_uploaded_evidence(uploaded_file)
        uploaded_headers = get_csv_headers(str(dataset_path))

        st.success(f"Evidence file received: {uploaded_file.name}")

        st.markdown("**Uploaded dataset preview**")

        preview = pd.read_csv(dataset_path, nrows=10)
        st.dataframe(
            preview,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            f"{len(uploaded_headers)} columns detected · "
            f"SHA-256: {upload_digest[:16]}..."
        )

    except Exception as exc:
        st.error(f"Could not read the uploaded CSV: {exc}")
        st.stop()

else:
    st.info(
        "No external file selected. The built-in synthetic sample dataset "
        "will be used when you run the investigation."
    )


column_mapping = None

with st.form("investigation_form"):
    if uploaded_file is not None and uploaded_headers:
        st.markdown("### CSV Column Mapping")
        st.caption(
            "Match your CSV headers to the framework's standard event fields. "
            "Suggestions are automatic; you can change them."
        )

        column_mapping = {}

        st.markdown("**Required fields**")

        for field in REQUIRED_FIELDS:
            suggestion = suggest_column(field, uploaded_headers)
            options = [UNMAPPED] + uploaded_headers

            default_index = (
                options.index(suggestion)
                if suggestion in options
                else 0
            )

            selected = st.selectbox(
                FIELD_LABELS[field],
                options,
                index=default_index,
                key=f"required_{field}",
            )

            column_mapping[field] = selected

        with st.expander("Optional fields", expanded=False):
            for field in OPTIONAL_FIELDS:
                suggestion = suggest_column(field, uploaded_headers)
                options = [UNMAPPED] + uploaded_headers

                default_index = (
                    options.index(suggestion)
                    if suggestion in options
                    else 0
                )

                selected = st.selectbox(
                    FIELD_LABELS[field],
                    options,
                    index=default_index,
                    key=f"optional_{field}",
                )

                column_mapping[field] = selected

    else:
        st.markdown("### Dataset Configuration")
        st.caption(
            "The built-in sample already follows the framework's standard "
            "event schema."
        )

    run_button = st.form_submit_button(
        "RUN FORENSIC INVESTIGATION",
        use_container_width=True,
    )


# ---------------------------------------------------------
# 7. INVESTIGATION EXECUTION
# ---------------------------------------------------------

if run_button:

    if not case_id.strip():
        st.error("Enter a valid investigation case ID.")

    elif uploaded_file is not None and any(
        column_mapping.get(field) == UNMAPPED
        for field in REQUIRED_FIELDS
    ):
        st.error(
            "Map all five required fields before starting the investigation."
        )

    else:
        try:
            raw_folder = PROJECT_ROOT / "data" / "raw"
            output_folder = PROJECT_ROOT / "data" / "processed"

            raw_folder.mkdir(parents=True, exist_ok=True)
            output_folder.mkdir(parents=True, exist_ok=True)

            if uploaded_file is not None:
                evidence_path = dataset_path
                evidence_source = "Uploaded CSV"
            else:
                evidence_path = raw_folder / "sample_events.csv"
                evidence_source = "Built-in synthetic sample dataset"

            if not evidence_path.exists():
                st.error("The selected evidence dataset does not exist.")

            else:
                with st.spinner(
                    "Verifying evidence and analysing security events..."
                ):

                    # A. Evidence integrity verification
                    evidence_hash = calculate_sha256(str(evidence_path))

                    evidence = EvidenceRecord(
                        evidence_id=f"EVD-{evidence_hash[:8].upper()}",
                        case_id=case_id.strip(),
                        source_type="csv_event_log",
                        file_path=str(evidence_path),
                        collected_at=current_utc_timestamp(),
                        sha256=evidence_hash,
                    )

                    # B. Event ingestion
                    if uploaded_file is not None:
                        normalized_mapping = {
                            field: selected
                            for field, selected in column_mapping.items()
                            if selected != UNMAPPED
                        }

                        events, errors = load_events_from_csv(
                            str(evidence_path),
                            expected_case_id=case_id.strip(),
                            column_mapping=normalized_mapping,
                        )
                    else:
                        events, errors = load_events_from_csv(
                            str(evidence_path),
                            expected_case_id=case_id.strip(),
                        )

                    # C. Rule-based detection
                    alerts = detect_brute_force_followed_by_success(events)

                    # D. Contextual correlation
                    correlations = correlate_alerts_with_events(
                        alerts,
                        events,
                    )

                    # E. Forensic timeline reconstruction
                    timeline, timeline_errors = build_event_timeline(events)

                    # F. ML feature extraction
                    feature_rows, feature_errors = extract_features(events)

                    # G. Isolation Forest anomaly detection
                    anomalies = []
                    anomaly_errors = []

                    if feature_errors or len(feature_rows) != len(events):
                        anomaly_errors.append(
                            "ML analysis skipped because feature extraction "
                            "was incomplete or event alignment was inconsistent."
                        )
                    elif feature_rows:
                        anomalies, anomaly_errors = detect_anomalies(
                            events,
                            feature_rows,
                        )

                    anomaly_findings = [
                        result for result in anomalies
                        if result["is_anomaly"] == 1
                    ]

                    # H. Assemble complete investigation report
                    report = {
                        "case_id": case_id.strip(),
                        "evidence": {
                            "evidence_id": evidence.evidence_id,
                            "source_type": evidence.source_type,
                            "file_path": evidence.file_path,
                            "collected_at": evidence.collected_at,
                            "sha256": evidence.sha256,
                        },
                        "evidence_source": evidence_source,
                        "total_events": len(events),
                        "ingestion_errors": errors,
                        "total_alerts": len(alerts),
                        "alerts": alerts,
                        "correlations": correlations,
                        "timeline": {
                            "total_events": len(timeline),
                            "processing_errors": timeline_errors,
                            "events": timeline,
                        },
                        "feature_extraction": {
                            "feature_count": (
                                len(feature_rows[0])
                                if feature_rows else 0
                            ),
                            "feature_errors": feature_errors,
                        },
                        "ml_analysis": {
                            "algorithm": "IsolationForest",
                            "total_events_analyzed": len(anomalies),
                            "anomaly_count": len(anomaly_findings),
                            "processing_errors": anomaly_errors,
                            "results": anomalies,
                        },
                    }

                    # I. Generate human-readable report
                    markdown_report = generate_markdown_report(report)

                    # J. Save JSON report
                    report_json = json.dumps(report, indent=4)

                    report_name = (
                        f"investigation_{case_id.strip()}_"
                        f"{evidence_hash[:10]}.json"
                    )

                    output_path = output_folder / report_name

                    output_path.write_text(
                        report_json,
                        encoding="utf-8",
                    )

                    # K. Save Markdown report
                    markdown_path = (
                        output_folder
                        / f"investigation_{case_id.strip()}_{evidence_hash[:10]}.md"
                    )

                    markdown_path.write_text(
                        markdown_report,
                        encoding="utf-8",
                    )

                # L. Store results for dashboard display
                st.session_state["investigation_report"] = report
                st.session_state["investigation_events"] = events
                st.session_state["investigation_source"] = evidence_source
                st.session_state["investigation_report_json"] = report_json
                st.session_state["investigation_report_markdown"] = markdown_report

                st.success("Investigation completed successfully.")

        except Exception as exc:
            st.error(f"Investigation failed: {exc}")
            st.exception(exc)



# ---------------------------------------------------------
# 8. INVESTIGATION RESULTS
# ---------------------------------------------------------

if "investigation_report" in st.session_state:

    report = st.session_state["investigation_report"]
    events = st.session_state["investigation_events"]

    alerts = report["alerts"]
    correlations = report["correlations"]
    related_count = get_related_count(correlations)

    st.divider()

    st.markdown(
        '<div class="section-label">02 / Investigation Results</div>',
        unsafe_allow_html=True,
    )

    st.subheader("Investigation Overview")

    st.caption(
        f"Case: {report['case_id']}  |  "
        f"Source: {st.session_state['investigation_source']}"
    )

    # Four investigation metrics
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card("EVENTS ANALYSED", report["total_events"])

    with c2:
        metric_card("RULE-BASED ALERTS", report["total_alerts"])

    with c3:
        metric_card("RELATED EVENTS", related_count)

    with c4:
        metric_card("INVALID RECORDS", len(report["ingestion_errors"]))

    st.markdown("<br>", unsafe_allow_html=True)

    # Result navigation
    overview_tab, evidence_tab, detection_tab, timeline_tab, report_tab = (
        st.tabs([
            "Overview",
            "Evidence Integrity",
            "Threat Analysis",
            "Forensic Timeline",
            "Investigation Report",
        ])
    )

    # -----------------------------------------------------
    # OVERVIEW TAB
    # -----------------------------------------------------

    with overview_tab:

        st.markdown("### Event Analytics")

        event_rows = [asdict(event) for event in events]
        event_df = pd.DataFrame(event_rows)

        if not event_df.empty:
            left, right = st.columns([1, 1])

            with left:
                st.markdown("**Event type distribution**")
                event_counts = event_df["event_type"].value_counts()
                st.bar_chart(event_counts)

            with right:
                st.markdown("**Log source distribution**")
                source_counts = event_df["source_type"].value_counts()
                st.bar_chart(source_counts)

            st.markdown("**Processed security events**")
            st.dataframe(
                event_df,
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.warning("No valid events were available for analysis.")

    # -----------------------------------------------------
    # EVIDENCE INTEGRITY TAB
    # -----------------------------------------------------

    with evidence_tab:

        evidence_data = report["evidence"]

        st.markdown("### Evidence Record")

        left, right = st.columns(2)

        with left:
            st.markdown(
                f"""
                <div class="panel">
                    <div class="panel-title">Evidence Identification</div>
                    <div class="panel-text">Evidence ID</div>
                    <b>{evidence_data['evidence_id']}</b>
                    <br><br>
                    <div class="panel-text">Case ID</div>
                    <b>{report['case_id']}</b>
                    <br><br>
                    <div class="panel-text">Source Type</div>
                    <b>{evidence_data['source_type']}</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with right:
            st.markdown(
                f"""
                <div class="panel">
                    <div class="panel-title">Acquisition Record</div>
                    <div class="panel-text">Recorded timestamp (UTC)</div>
                    <b>{evidence_data['collected_at']}</b>
                    <br><br>
                    <div class="panel-text">Evidence source</div>
                    <b>{report['evidence_source']}</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("### SHA-256 Integrity Hash")

        st.markdown(
            f'<div class="hash-box">{evidence_data["sha256"]}</div>',
            unsafe_allow_html=True,
        )

        st.caption(
            "This hash identifies the current file content and can be "
            "used for subsequent integrity comparisons. It does not, by "
            "itself, establish source authenticity or a complete chain of custody."
        )

        st.markdown("**Evidence file location**")
        st.code(evidence_data["file_path"])

    # -----------------------------------------------------
    # THREAT ANALYSIS TAB
    # -----------------------------------------------------

    with detection_tab:

        st.markdown("### Rule-Based Threat Detection")

        if alerts:

            for index, alert in enumerate(alerts, start=1):

                severity = str(alert.get("severity", "UNSPECIFIED")).upper()
                rule = alert.get("alert_rule", "Detection alert")
                description = alert.get(
                    "description",
                    "Suspicious activity identified by a configured rule.",
                )

                st.markdown(
                    f"""
                    <div class="alert-card">
                        <div class="section-label">ALERT {index} · {severity}</div>
                        <div class="panel-title">{rule}</div>
                        <div class="panel-text">{description}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                with st.expander("View detection details"):
                    st.write("Severity:", severity)
                    st.write("Detection rule:", rule)

                    for key, value in alert.items():
                        if key not in ["severity", "alert_rule", "description"]:
                            st.write(f"**{key.replace('_', ' ').title()}:**", value)

        else:
            st.success(
                "No alerts were generated by the configured detection rule."
            )

        st.markdown("---")
        st.markdown("### Contextual Event Correlation")

        if correlations:

            for correlation in correlations:

                st.markdown(
                    f"""
                    <div class="panel">
                        <div class="panel-title">
                            {correlation.get('alert_rule', 'Related activity')}
                        </div>
                        <div class="panel-text">
                            {correlation.get('related_event_count', 0)}
                            related event(s) identified
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                related_events = correlation.get("related_events", [])

                if related_events:
                    st.dataframe(
                        pd.DataFrame(related_events),
                        use_container_width=True,
                        hide_index=True,
                    )

        else:
            st.info("No related events were identified.")

        st.caption(
            "A correlation indicates contextual similarity based on the "
            "implemented matching criteria; it does not prove causation."
        )

        # -------------------------------------------------
        # AI-ASSISTED ANOMALY ANALYSIS
        # -------------------------------------------------
        st.markdown("---")
        st.markdown("### AI-Assisted Anomaly Analysis")

        ml_analysis = report.get("ml_analysis", {})
        ml_results = ml_analysis.get("results", [])

        anomaly_findings = [
            result for result in ml_results
            if result.get("is_anomaly") == 1
        ]

        ml_col1, ml_col2, ml_col3 = st.columns(3)

        with ml_col1:
            st.metric(
                "Events Analysed by ML",
                ml_analysis.get("total_events_analyzed", 0),
            )

        with ml_col2:
            st.metric(
                "Anomalies Identified",
                ml_analysis.get("anomaly_count", 0),
            )

        with ml_col3:
            st.metric(
                "Features Extracted",
                report.get("feature_extraction", {}).get(
                    "feature_count", 0
                ),
            )

        if anomaly_findings:
            st.markdown("#### Anomalous Events")

            anomaly_df = pd.DataFrame(anomaly_findings)

            st.dataframe(
                anomaly_df,
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.info(
                "No anomalies were identified by the Isolation Forest "
                "model in the analysed events."
            )

        ml_errors = ml_analysis.get("processing_errors", [])

        feature_errors = report.get(
            "feature_extraction", {}
        ).get("feature_errors", [])

        if ml_errors or feature_errors:
            with st.expander("View ML processing warnings"):

                for error in feature_errors:
                    st.warning(f"Feature extraction: {error}")

                for error in ml_errors:
                    st.warning(f"ML analysis: {error}")

        st.caption(
            "Isolation Forest provides exploratory anomaly indicators. "
            "An anomaly is not necessarily malicious, and these results "
            "do not represent validated detection accuracy."
        )
    # -----------------------------------------------------
    # FORENSIC TIMELINE TAB
    # -----------------------------------------------------

    with timeline_tab:

        st.markdown("### Chronological Event Timeline")

        timeline_df = pd.DataFrame(
            [asdict(event) for event in events]
        )

        if not timeline_df.empty:

            timeline_df["parsed_timestamp"] = pd.to_datetime(
                timeline_df["timestamp"],
                errors="coerce",
                utc=True,
            )

            timeline_df = timeline_df.sort_values(
                "parsed_timestamp",
                na_position="last",
            )

            display_columns = [
                column
                for column in [
                    "timestamp",
                    "event_id",
                    "event_type",
                    "source_type",
                    "host",
                    "user",
                    "source_ip",
                    "destination_ip",
                    "process_name",
                ]
                if column in timeline_df.columns
            ]

            st.dataframe(
                timeline_df[display_columns],
                use_container_width=True,
                hide_index=True,
            )

            st.caption(
                "Events are ordered by their parsed timestamps. "
                "This is a basic event timeline, not a reconstructed attack timeline."
            )

        else:
            st.info("No events are available to construct a timeline.")

    # -----------------------------------------------------
    # INVESTIGATION REPORT TAB
    # -----------------------------------------------------

    with report_tab:

        st.markdown("### Investigation Report")

        st.markdown("""
        The report contains:

        - Investigation case details
        - Evidence identification and SHA-256 hash
        - Event ingestion results
        - Rule-based detection alerts
        - Contextual event correlations
        - Forensic timeline
        - AI anomaly analysis
        """)

        report_json = st.session_state["investigation_report_json"]

        # -------------------------------------------------
        # JSON REPORT DOWNLOAD
        # -------------------------------------------------

        st.download_button(
            "DOWNLOAD INVESTIGATION REPORT (JSON)",
            data=report_json,
            file_name=f"investigation_{report['case_id']}.json",
            mime="application/json",
            use_container_width=True,
        )

        # -------------------------------------------------
        # PDF REPORT DOWNLOAD
        # -------------------------------------------------

        pdf_report = generate_pdf_report(report)

        st.download_button(
            "DOWNLOAD INVESTIGATION REPORT (PDF)",
            data=pdf_report,
            file_name=f"investigation_{report['case_id']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

        # -------------------------------------------------
        # VIEW JSON REPORT
        # -------------------------------------------------

        with st.expander("View technical JSON output"):
            st.code(report_json, language="json")

        # -------------------------------------------------
        # INGESTION VALIDATION ISSUES
        # -------------------------------------------------

        if report["ingestion_errors"]:

            st.markdown("### Ingestion Validation Issues")

            for error in report["ingestion_errors"]:
                st.warning(str(error))

