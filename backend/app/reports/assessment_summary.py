"""
ZeroTrace Security Assessment Summary PDF Report Generator.
Generates a concise, professional, and developer-friendly website scan summary report (1–3 pages).
Features target metrics, security score, severity breakdown, unique vulnerability inventory,
and actionable technical remediation guidance without bloated theoretical filler.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging_config import redact
from app.reports.bug_bounty_report import (
    extract_finding_details,
    get_cvss_info,
    group_findings_into_unique,
    sanitize_evidence,
)
from app.services.security_posture import calculate_security_posture

SEV_COLORS = {
    "Critical": "#991b1b",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#ca8a04",
    "Informational": "#2563eb",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


class SummaryNumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic 'Page X of Y' numbering and running headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header on page 2 and later
        if self._pageNumber > 1:
            self.drawString(14 * mm, 285 * mm, "ZeroTrace — Security Assessment Summary")
            self.setFont("Helvetica", 8)
            self.drawRightString(196 * mm, 285 * mm, "CONFIDENTIAL & PROPRIETARY")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(14 * mm, 283 * mm, 196 * mm, 283 * mm)

        # Running Footer on all pages
        self.setFont("Helvetica", 8)
        self.drawString(14 * mm, 10 * mm, "ZeroTrace Automated Web Vulnerability Assessment Platform")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(196 * mm, 10 * mm, page_text)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(14 * mm, 13 * mm, 196 * mm, 13 * mm)
        self.restoreState()


def _p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(sanitize_evidence(str(text or ""))), style)


def build_assessment_summary_pdf(scan, findings, summary=None) -> bytes:
    """
    Generate a concise, developer-friendly 1–3 page Security Assessment Summary PDF.
    Contains:
    - Website URL and scan date
    - Total unique vulnerabilities & security score
    - Severity breakdown matrix
    - Vulnerability names and affected endpoints table
    - Short descriptions and recommended fixes
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="ZeroTrace — Security Assessment Summary",
        author="ZeroTrace Vulnerability Assessment Platform",
    )

    ss = getSampleStyleSheet()

    # Compact typography
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0f172a"), fontSize=10, leading=13, spaceBefore=4, spaceAfter=2)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8, leading=10.5, textColor=colors.HexColor("#1e293b"))
    body_bold = ParagraphStyle("body_bold", parent=body, fontName="Helvetica-Bold")
    small = ParagraphStyle("small", parent=body, fontSize=7, leading=9, textColor=colors.HexColor("#475569"))
    small_bold = ParagraphStyle("small_bold", parent=small, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=6.8, leading=8.5, textColor=colors.HexColor("#0f172a"))

    posture = calculate_security_posture(scan, findings)
    target_url = getattr(scan.target, "base_url", "Unknown Target") if getattr(scan, "target", None) else "Target"
    hostname = posture.get("hostname") or urlparse(target_url).hostname or "target-host"
    scan_id = getattr(scan, "id", "")
    created_at = getattr(scan, "created_at", None) or datetime.now(timezone.utc)
    app_name = getattr(getattr(scan, "application", None), "name", None)

    # Group findings into unique vulnerabilities to prevent inflation
    unique_vulns = group_findings_into_unique(findings)
    total_unique = len(unique_vulns)
    total_raw = len(findings)

    story = []

    # 1. Header Banner
    header_tbl = Table(
        [
            [
                Paragraph("<b>ZeroTrace</b> — Security Assessment Summary", ParagraphStyle("hdr_title", parent=body, fontSize=11, textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold")),
                Paragraph("WEBSITE SECURITY REPORT", ParagraphStyle("hdr_sub", parent=body, fontSize=8.5, textColor=colors.HexColor("#0284c7"), fontName="Helvetica-Bold", alignment=2)),
            ]
        ],
        colWidths=[120 * mm, 62 * mm],
    )
    header_tbl.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#0284c7")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 2.5 * mm))

    # 2. Score & Key Metrics Banner
    score = posture.get("score", 100.0)
    rating = posture.get("rating", "STRONG")
    rating_color_hex = posture.get("rating_color", "#10b981")
    rating_color = colors.HexColor(rating_color_hex)
    duration_str = f"{scan.duration_seconds:.1f}s" if getattr(scan, "duration_seconds", None) else "N/A"

    score_card_content = [
        [
            Paragraph(f"<font size=20><b>{score:.0f}</b></font><font size=9>/100</font><br/><font size=7 color='#475569'>SECURITY SCORE</font>", ParagraphStyle("sc_c", parent=body, alignment=1)),
            Paragraph(f"<font size=11 color='white'><b>{rating} POSTURE</b></font><br/><font size=6.5 color='#f1f5f9'>OWASP Web Top 10 Evaluation</font>", ParagraphStyle("rt_c", parent=body, alignment=1)),
            Paragraph(f"<b>Target:</b> {escape(target_url[:50])}<br/>"
                      f"<b>Date:</b> {created_at:%Y-%m-%d %H:%M} UTC &nbsp;|&nbsp; <b>Duration:</b> {duration_str}<br/>"
                      f"<b>Unique Vulnerabilities:</b> {total_unique} &nbsp;|&nbsp; <b>Raw Occurrences:</b> {total_raw}", small),
        ]
    ]
    score_card = Table(score_card_content, colWidths=[34 * mm, 50 * mm, 98 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (1, 0), (1, 0), rating_color),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(score_card)
    story.append(Spacer(1, 2.5 * mm))

    # 3. Severity Breakdown Matrix
    sev_matrix_data = [
        [
            Paragraph("<b>Severity Tier</b>", small_bold),
            Paragraph("<b>Unique Issues</b>", small_bold),
            Paragraph("<b>Raw Occurrences</b>", small_bold),
            Paragraph("<b>Risk Description & Potential Impact</b>", small_bold),
        ]
    ]
    sev_desc = {
        "Critical": "Direct remote code execution, database compromise, or administrative authentication bypass.",
        "High": "High-impact data exfiltration, blind SQLi, persistent XSS, or privileged state manipulation.",
        "Medium": "Reflected XSS, CSRF, sensitive information exposure, or weak session configurations.",
        "Low": "Missing defense-in-depth headers, clickjacking risk, or verbose server banners.",
        "Informational": "Discovered endpoints, structural fingerprinting, and attack surface context.",
    }
    for s_name in SEV_ORDER:
        u_cnt = sum(1 for u in unique_vulns if u["severity"].lower() == s_name.lower())
        r_cnt = sum(u["occurrences"] for u in unique_vulns if u["severity"].lower() == s_name.lower())
        s_hex = SEV_COLORS.get(s_name, "#475569")
        sev_matrix_data.append([
            Paragraph(f"<font color='{s_hex}'><b>● {s_name}</b></font>", small),
            Paragraph(f"<b>{u_cnt}</b>", small),
            Paragraph(str(r_cnt), small),
            Paragraph(sev_desc.get(s_name, ""), small),
        ])
    sev_table = Table(sev_matrix_data, colWidths=[26 * mm, 24 * mm, 26 * mm, 106 * mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 1.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 3 * mm))

    # 4. Vulnerability Findings Inventory Table
    story.append(Paragraph("<b>1. Vulnerability Findings Inventory</b>", h1))
    if not unique_vulns:
        no_conf_box = Table(
            [[Paragraph("<b>✓ Zero Vulnerabilities Detected</b><br/>"
                        "Automated scanning did not identify vulnerabilities within the target crawl boundaries. "
                        "Security baselines and defense-in-depth configurations should continue to be maintained.", body)]],
            colWidths=[182 * mm],
        )
        no_conf_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#10b981")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(no_conf_box)
        story.append(Spacer(1, 3 * mm))
    else:
        summary_rows = [
            [
                Paragraph("<b>#</b>", small_bold),
                Paragraph("<b>Severity</b>", small_bold),
                Paragraph("<b>Vulnerability Name</b>", small_bold),
                Paragraph("<b>Primary Endpoint</b>", small_bold),
                Paragraph("<b>Param / Header</b>", small_bold),
                Paragraph("<b>Scope</b>", small_bold),
            ]
        ]
        for idx, u in enumerate(unique_vulns, 1):
            s_val = (u["severity"] or "").capitalize()
            s_hex = SEV_COLORS.get(s_val, "#475569")
            prim_url = u["url"] or target_url
            path = urlparse(prim_url).path or "/"
            param_str = u["parameter"] if u["parameter"] != "None" else "—"
            scope_str = f"{len(u['affected_urls'])} route(s) ({u['occurrences']} hit{'s' if u['occurrences'] > 1 else ''})"

            summary_rows.append([
                Paragraph(str(idx), small),
                Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()}</b></font>", small),
                Paragraph(f"<b>{escape(u['type'])}</b>", small),
                Paragraph(f"<code>{escape(u['method'])} {escape(path[:25])}</code>", small),
                Paragraph(escape(str(param_str)[:18]), small),
                Paragraph(escape(scope_str), small),
            ])

        summary_tbl = Table(summary_rows, colWidths=[8 * mm, 22 * mm, 52 * mm, 46 * mm, 26 * mm, 28 * mm])
        summary_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 1.8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(summary_tbl)
        story.append(Spacer(1, 3.5 * mm))

        # 5. Concise Technical Findings & Recommended Fixes (Cards)
        story.append(Paragraph("<b>2. Technical Findings & Actionable Fixes</b>", h1))
        for idx, u in enumerate(unique_vulns, 1):
            rep = u["representative"]
            f_det = extract_finding_details(rep)
            s_val = (u["severity"] or "").capitalize()
            s_hex = SEV_COLORS.get(s_val, "#475569")
            prim_url = u["url"] or target_url
            path = urlparse(prim_url).path or "/"
            scope_text = f"{len(u['affected_urls'])} endpoint(s), {u['occurrences']} raw hit(s)" if u["occurrences"] > 1 else "Single endpoint"

            card_rows = [
                [
                    Paragraph(f"<b>{idx}. {escape(u['type'].upper())}</b> &nbsp;<font color='#64748b'>({escape(str(u['detection_status']))})</font>", ParagraphStyle("tc_t", parent=body_bold, fontSize=8, textColor=colors.HexColor("#0f172a"))),
                    Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()}</b></font>", ParagraphStyle("tc_s", parent=small_bold, alignment=2)),
                ],
                [
                    Paragraph(
                        f"<b>Endpoint:</b> <code>{escape(u['method'])} {escape(path)}</code> &nbsp;|&nbsp; "
                        f"<b>Input / Param:</b> <code>{escape(str(f_det['parameter']))}</code> &nbsp;|&nbsp; "
                        f"<b>Scope:</b> {escape(scope_text)}<br/>"
                        f"<b>Description:</b> {escape(f_det['short_explanation'])}",
                        small,
                    ),
                    "",
                ],
                [
                    Paragraph(
                        f"<b>Observed Result:</b> {escape(f_det['observed_result'][:200])}<br/>"
                        f"<b>Impact:</b> {escape(f_det['potential_impact'][:140])}<br/>"
                        f"<b>Recommended Fix:</b> {escape(f_det['recommended_fix'])}",
                        small,
                    ),
                    "",
                ],
            ]

            card_tbl = Table(card_rows, colWidths=[130 * mm, 52 * mm])
            card_tbl.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 1.6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
            ]))
            story.append(KeepTogether([card_tbl, Spacer(1, 2 * mm)]))

    doc.build(story, canvasmaker=SummaryNumberedCanvas)
    return buf.getvalue()
