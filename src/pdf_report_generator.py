from io import BytesIO
from html import escape
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def generate_pdf_report(report):
    """
    Generate a PDF investigation report from the dashboard report dictionary.

    Returns:
        PDF file as bytes.
    """

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="Digital Forensic Investigation Report",
        author="Forensic Insight",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=25,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=body_style,
        fontSize=7.5,
        leading=10,
    )

    story = []

    # -------------------------------------------------
    # HELPER FUNCTIONS
    # -------------------------------------------------

    def safe_text(value):
        if value is None:
            return "N/A"

        if isinstance(value, (dict, list)):
            value = str(value)

        return escape(str(value))

    def add_heading(text):
        story.append(Paragraph(safe_text(text), heading_style))

    def add_paragraph(text):
        story.append(Paragraph(safe_text(text), body_style))

    def add_table(headers, rows):
        table_data = [
            [Paragraph(f"<b>{safe_text(h)}</b>", small_style) for h in headers]
        ]

        for row in rows:
            table_data.append(
                [
                    Paragraph(safe_text(cell), small_style)
                    for cell in row
                ]
            )

        if len(table_data) == 1:
            return

        page_width = A4[0] - 36 * mm

        col_widths = [page_width / len(headers)] * len(headers)

        table = Table(
            table_data,
            colWidths=col_widths,
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F1")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17365D")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(table)
        story.append(Spacer(1, 8))

    def add_footer(canvas, document):
        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            18 * mm,
            10 * mm,
            "Forensic Insight | AI-Augmented Digital Forensics",
        )

        canvas.drawRightString(
            A4[0] - 18 * mm,
            10 * mm,
            f"Page {document.page}",
        )

        canvas.restoreState()

    # -------------------------------------------------
    # TITLE
    # -------------------------------------------------

    story.append(
        Paragraph(
            "DIGITAL FORENSIC<br/>INVESTIGATION REPORT",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "AI-Augmented Digital Forensics and Threat Correlation Framework",
            ParagraphStyle(
                "Subtitle",
                parent=body_style,
                alignment=TA_CENTER,
                fontSize=10,
                textColor=colors.grey,
                spaceAfter=15,
            ),
        )
    )

    case_id = report.get("case_id", "N/A")

    story.append(
        Paragraph(
            f"<b>Investigation Case ID:</b> {safe_text(case_id)}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Report Generated:</b> "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            body_style,
        )
    )

    story.append(Spacer(1, 10))

    # -------------------------------------------------
    # CASE OVERVIEW
    # -------------------------------------------------

    add_heading("1. Case Overview")

    overview_rows = [
        ["Case ID", case_id],
        ["Total Events Analysed", report.get("total_events", 0)],
        ["Rule-Based Alerts", report.get("total_alerts", 0)],
        [
            "Correlated Event Groups",
            len(report.get("correlations", [])),
        ],
        [
            "Timeline Events",
            len(report.get("timeline", {}).get("events", [])),
        ],
        [
            "ML Anomalies Identified",
            report.get("ml_analysis", {}).get("anomaly_count", 0),
        ],
    ]

    add_table(["Parameter", "Value"], overview_rows)

    # -------------------------------------------------
    # EVIDENCE INFORMATION
    # -------------------------------------------------

    add_heading("2. Evidence & Integrity Information")

    evidence = report.get("evidence", {})

    if isinstance(evidence, dict):
        evidence_rows = [
            ["Evidence Source", report.get("evidence_source", "N/A")],
            ["Evidence Filename", evidence.get("filename", "N/A")],
            ["SHA-256 Hash", evidence.get("sha256", "N/A")],
            ["Evidence Size (Bytes)", evidence.get("file_size", "N/A")],
        ]

        add_table(["Evidence Property", "Value"], evidence_rows)

    else:
        add_paragraph(
            "Evidence metadata was not available in the expected format."
        )

    add_paragraph(
        "SHA-256 hashing is used to support integrity verification "
        "by comparing hash values. A matching hash alone does not "
        "establish authenticity or complete chain of custody."
    )

    # -------------------------------------------------
    # INGESTION
    # -------------------------------------------------

    add_heading("3. Event Ingestion Summary")

    ingestion_errors = report.get("ingestion_errors", [])

    add_paragraph(
        f"Total events processed: {report.get('total_events', 0)}"
    )

    add_paragraph(
        f"Ingestion errors: {len(ingestion_errors)}"
    )

    if ingestion_errors:
        for error in ingestion_errors:
            add_paragraph(f"Ingestion warning: {error}")

    # -------------------------------------------------
    # RULE-BASED DETECTION
    # -------------------------------------------------

    add_heading("4. Rule-Based Threat Detection")

    alerts = report.get("alerts", [])

    if alerts:
        alert_rows = []

        for alert in alerts:
            alert_rows.append(
                [
                    alert.get("alert_id", "N/A"),
                    alert.get("severity", "N/A"),
                    alert.get("description", "N/A"),
                    alert.get("source_ip", "N/A"),
                    alert.get("user", "N/A"),
                ]
            )

        add_table(
            ["Alert ID", "Severity", "Description", "Source IP", "User"],
            alert_rows,
        )

    else:
        add_paragraph("No rule-based alerts were generated.")

    # -------------------------------------------------
    # CORRELATION
    # -------------------------------------------------

    add_heading("5. Contextual Event Correlation")

    correlations = report.get("correlations", [])

    if correlations:

        for index, correlation in enumerate(correlations, start=1):

            story.append(
                Paragraph(
                    f"<b>Correlation Group {index}</b>",
                    body_style,
                )
            )

            add_paragraph(
                f"Alert ID: {correlation.get('alert_id', 'N/A')}"
            )

            related_events = correlation.get("related_events", [])

            if related_events:

                correlation_rows = []

                for event in related_events:
                    correlation_rows.append(
                        [
                            event.get("event_id", "N/A"),
                            event.get("event_type", "N/A"),
                            event.get("timestamp", "N/A"),
                            event.get("process_name", "N/A"),
                            event.get("source_ip", "N/A"),
                            event.get("destination_ip", "N/A"),
                        ]
                    )

                add_table(
                    [
                        "Event ID",
                        "Event Type",
                        "Timestamp",
                        "Process",
                        "Source IP",
                        "Destination IP",
                    ],
                    correlation_rows,
                )

    else:
        add_paragraph("No contextual correlations were identified.")

    add_paragraph(
        "Correlation indicates contextual relationships based on "
        "implemented matching criteria and does not prove causation."
    )

    # -------------------------------------------------
    # FORENSIC TIMELINE
    # -------------------------------------------------

    add_heading("6. Forensic Event Timeline")

    timeline_data = report.get("timeline", {})
    timeline_events = timeline_data.get("events", [])

    if timeline_events:

        timeline_rows = []

        for event in timeline_events:
            timeline_rows.append(
                [
                    event.get("timestamp", "N/A"),
                    event.get("event_id", "N/A"),
                    event.get("event_type", "N/A"),
                    event.get("user", "N/A"),
                    event.get("host", "N/A"),
                    event.get("process_name", "N/A"),
                    event.get("source_ip", "N/A"),
                ]
            )

        add_table(
            [
                "Timestamp",
                "Event ID",
                "Event Type",
                "User",
                "Host",
                "Process",
                "Source IP",
            ],
            timeline_rows,
        )

    else:
        add_paragraph("No timeline events were available.")

    timeline_errors = timeline_data.get("processing_errors", [])

    if timeline_errors:
        for error in timeline_errors:
            add_paragraph(f"Timeline processing warning: {error}")

    # -------------------------------------------------
    # AI ANOMALY ANALYSIS
    # -------------------------------------------------

    add_heading("7. AI-Assisted Anomaly Analysis")

    ml_analysis = report.get("ml_analysis", {})
    ml_results = ml_analysis.get("results", [])

    add_paragraph(
        f"Algorithm: {ml_analysis.get('algorithm', 'N/A')}"
    )

    add_paragraph(
        f"Events Analysed: "
        f"{ml_analysis.get('total_events_analyzed', 0)}"
    )

    add_paragraph(
        f"Anomalies Identified: "
        f"{ml_analysis.get('anomaly_count', 0)}"
    )

    anomaly_results = [
        result for result in ml_results
        if result.get("is_anomaly") == 1
    ]

    if anomaly_results:

        anomaly_rows = []

        for result in anomaly_results:
            anomaly_rows.append(
                [
                    result.get("event_id", "N/A"),
                    result.get("classification", "N/A"),
                    result.get("anomaly_score", "N/A"),
                ]
            )

        add_table(
            ["Event ID", "Classification", "Anomaly Score"],
            anomaly_rows,
        )

    else:
        add_paragraph(
            "No anomalous events were identified by the model."
        )

    add_paragraph(
        "Machine-learning anomaly indicators represent unusual "
        "patterns within the analysed dataset. An anomaly is not "
        "necessarily malicious. These results do not represent "
        "validated detection accuracy."
    )

    # -------------------------------------------------
    # FEATURE EXTRACTION
    # -------------------------------------------------

    add_heading("8. Feature Extraction")

    feature_info = report.get("feature_extraction", {})

    add_paragraph(
        f"Features Extracted: "
        f"{feature_info.get('feature_count', 0)}"
    )

    feature_errors = feature_info.get("feature_errors", [])

    if feature_errors:
        for error in feature_errors:
            add_paragraph(f"Feature extraction warning: {error}")

    # -------------------------------------------------
    # PROCESSING WARNINGS
    # -------------------------------------------------

    add_heading("9. Processing Warnings")

    warnings = (
        ingestion_errors
        + timeline_errors
        + feature_errors
        + ml_analysis.get("processing_errors", [])
    )

    if warnings:
        for warning in warnings:
            add_paragraph(str(warning))
    else:
        add_paragraph("No processing warnings were recorded.")

    # -------------------------------------------------
    # LIMITATIONS
    # -------------------------------------------------

    add_heading("10. Analysis Limitations")

    limitations = [
        "The analysis is based on the events available in the supplied dataset.",
        "Rule-based alerts identify patterns matching predefined conditions.",
        "Contextual event correlation does not establish causality.",
        "Machine-learning anomalies are indicators of unusual behaviour "
        "and do not independently confirm malicious activity.",
        "The current demonstration dataset does not establish "
        "real-world detection accuracy or generalisation.",
        "Investigator review is required before drawing conclusions "
        "about an incident.",
    ]

    for limitation in limitations:
        add_paragraph(f"- {limitation}")

    # -------------------------------------------------
    # FINAL PDF BUILD
    # -------------------------------------------------

    doc.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer,
    )

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes