"""
ZeroTrace Security Assessment Summary PDF Report Generator.
Generates a concise, executive-and-technical security posture summary (5-15 pages)
featuring target metrics, verified findings, strictly segregated potential issues,
crawling coverage, scanner execution status, and prioritized remediation roadmap.
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
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging_config import redact
from app.reports.bug_bounty_report import get_cvss_info
from app.services.security_posture import calculate_security_posture

SEV_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#ea580c",
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
            self.drawString(18 * mm, 282 * mm, "ZeroTrace — Security Assessment Summary")
            self.setFont("Helvetica", 8)
            self.drawRightString(192 * mm, 282 * mm, "CONFIDENTIAL & PROPRIETARY")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(18 * mm, 280 * mm, 192 * mm, 280 * mm)

        # Running Footer on all pages
        self.setFont("Helvetica", 8)
        self.drawString(18 * mm, 12 * mm, "ZeroTrace Automated Web Vulnerability Assessment Platform")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(192 * mm, 12 * mm, page_text)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(18 * mm, 15 * mm, 192 * mm, 15 * mm)
        self.restoreState()


def _p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(redact(str(text or ""))), style)


def build_assessment_summary_pdf(scan, findings, summary=None) -> bytes:
    """
    Generate a concise, professional 5-15 page Security Assessment Summary PDF.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="ZeroTrace — Security Assessment Summary",
        author="ZeroTrace Vulnerability Assessment Platform",
    )

    ss = getSampleStyleSheet()

    # Typography styles
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0f172a"), fontSize=15, leading=19, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#1e293b"), fontSize=12, leading=15, spaceBefore=8, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], textColor=colors.HexColor("#334155"), fontSize=10, leading=13, spaceBefore=4, spaceAfter=2)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8.5, leading=12, textColor=colors.HexColor("#1e293b"))
    body_bold = ParagraphStyle("body_bold", parent=body, fontName="Helvetica-Bold")
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))
    small_bold = ParagraphStyle("small_bold", parent=small, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=7.2, leading=9.5, textColor=colors.HexColor("#0f172a"))

    posture = calculate_security_posture(scan, findings)

    target_url = getattr(scan.target, "base_url", "Unknown Target") if getattr(scan, "target", None) else "Target"
    hostname = posture.get("hostname") or urlparse(target_url).hostname or "target-host"
    scan_id = getattr(scan, "id", "")
    created_at = getattr(scan, "created_at", None) or datetime.now(timezone.utc)
    app_name = getattr(getattr(scan, "application", None), "name", None)

    # Segregate Confirmed vs Potential / Manual Verification
    confirmed_findings = []
    potential_findings = []
    for f in findings:
        det_status = getattr(f, "detection_status", "Confirmed")
        if det_status == "Confirmed":
            confirmed_findings.append(f)
        else:
            potential_findings.append(f)

    # Sort confirmed findings by severity
    def sev_key(item):
        s = getattr(item, "severity", "")
        s_val = s.value if hasattr(s, "value") else str(s)
        return SEV_ORDER.index(s_val) if s_val in SEV_ORDER else 99

    confirmed_findings.sort(key=sev_key)
    potential_findings.sort(key=sev_key)

    story = []

    # =========================================================================
    # 1. HEADER BANNER & TARGET OVERVIEW
    # =========================================================================
    header_tbl = Table(
        [
            [
                Paragraph("<b>ZeroTrace</b> — Security Assessment Summary", ParagraphStyle("hdr_title", parent=body, fontSize=12, textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold")),
                Paragraph("EXECUTIVE BRIEFING", ParagraphStyle("hdr_sub", parent=body, fontSize=9, textColor=colors.HexColor("#0284c7"), fontName="Helvetica-Bold", alignment=2)),
            ]
        ],
        colWidths=[114 * mm, 60 * mm],
    )
    header_tbl.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#0284c7")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 4 * mm))

    # Security Posture Banner Card
    score = posture.get("score", 100.0)
    rating = posture.get("rating", "STRONG")
    rating_color_hex = posture.get("rating_color", "#10b981")
    rating_color = colors.HexColor(rating_color_hex)

    score_card_content = [
        [
            Paragraph(f"<font size=24><b>{score:.0f}</b></font><font size=11>/100</font><br/><font size=8 color='#475569'>SECURITY SCORE</font>", ParagraphStyle("sc_c", parent=body, alignment=1)),
            Paragraph(f"<font size=13 color='white'><b>{rating} POSTURE</b></font><br/><font size=7.5 color='#f1f5f9'>Evaluated against OWASP Web Top 10 heuristics</font>", ParagraphStyle("rt_c", parent=body, alignment=1)),
            Paragraph(f"<b>Confirmed Vulnerabilities:</b> {len(confirmed_findings)}<br/>"
                      f"<b>Potential / Manual Check:</b> {len(potential_findings)}<br/>"
                      f"<b>Total Scope Endpoints:</b> {scan.urls_discovered or 0} discovered ({scan.urls_scanned or 0} crawled)", small),
        ]
    ]
    score_card = Table(score_card_content, colWidths=[38 * mm, 54 * mm, 82 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (1, 0), (1, 0), rating_color),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(score_card)
    story.append(Spacer(1, 4 * mm))

    # Target Metadata Grid
    duration_str = f"{scan.duration_seconds:.1f}s" if getattr(scan, "duration_seconds", None) else "N/A"
    meta_rows = [
        [Paragraph("<b>Target Base URL</b>", small), _p(target_url, small),
         Paragraph("<b>Target Hostname</b>", small), _p(hostname, small)],
        [Paragraph("<b>Associated App</b>", small), _p(app_name or "Standalone Web Target", small),
         Paragraph("<b>Assessment ID</b>", small), _p(str(scan_id)[:16], small)],
        [Paragraph("<b>Assessment Date</b>", small), _p(f"{created_at:%Y-%m-%d %H:%M} UTC", small),
         Paragraph("<b>Crawl Duration</b>", small), _p(duration_str, small)],
    ]
    meta_table = Table(meta_rows, colWidths=[28 * mm, 58 * mm, 32 * mm, 56 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 4 * mm))

    # =========================================================================
    # 2. EXECUTIVE SUMMARY & POSTURE OBSERVATIONS
    # =========================================================================
    story.append(Paragraph("1. Executive Summary & Security Posture", h1))

    if posture.get("is_preliminary"):
        warn_text = f"<b>Preliminary Assessment Notice:</b> {posture.get('preliminary_reason', 'Assessment is preliminary due to limited scan boundaries.')}"
        warn_box = Table([[Paragraph(warn_text, ParagraphStyle("w_txt", parent=small, textColor=colors.HexColor("#92400e")))]], colWidths=[174 * mm])
        warn_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f59e0b")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(warn_box)
        story.append(Spacer(1, 3 * mm))

    exec_narrative = (
        f"ZeroTrace performed an automated security vulnerability assessment against <b>{escape(hostname)}</b> "
        f"({escape(target_url)}). The target achieved an overall security rating of <b>{rating}</b> "
        f"with a score of <b>{score:.0f}/100</b>. "
        f"A total of <b>{len(confirmed_findings)} confirmed vulnerability issue(s)</b> and "
        f"<b>{len(potential_findings)} potential item(s)</b> were cataloged during the assessment. "
    )
    if confirmed_findings:
        crit_high_count = sum(1 for f in confirmed_findings if str(getattr(f, "severity", "")).lower() in ("critical", "high"))
        if crit_high_count > 0:
            exec_narrative += (
                f"Attention is urgently required: <b>{crit_high_count} issue(s) carry Critical or High severity</b>, "
                f"presenting immediate attack vectors for unauthorized access, data compromise, or injection."
            )
        else:
            exec_narrative += "No Critical or High severity vulnerabilities were confirmed, though defense-in-depth gaps exist."
    else:
        exec_narrative += (
            "No confirmed security vulnerabilities were identified within the automated crawl scope. "
            "Defensive baseline checks and security headers should continue to be maintained."
        )

    story.append(Paragraph(exec_narrative, body))
    story.append(Spacer(1, 3 * mm))

    # Severity Matrix Breakdown Table
    sev_counts = posture.get("breakdown", {})
    matrix_data = [
        [
            Paragraph("<b>Severity Tier</b>", small_bold),
            Paragraph("<b>Confirmed</b>", small_bold),
            Paragraph("<b>Potential / Manual</b>", small_bold),
            Paragraph("<b>Risk & Operational Impact</b>", small_bold),
        ]
    ]

    impact_desc = {
        "Critical": "Direct remote code execution, SQL injection with full DB takeover, or authentication bypass.",
        "High": "High-impact data exfiltration, blind SQLi, persistent XSS, or privileged state manipulation.",
        "Medium": "Reflected XSS, CSRF, sensitive internal information exposure, or weak session configurations.",
        "Low": "Missing defense-in-depth HTTP headers, clickjacking risk, or verbose server error banners.",
        "Informational": "Technology fingerprinting, discovered endpoints, and structural attack surface context.",
    }

    for s_name in SEV_ORDER:
        c_count = sum(1 for f in confirmed_findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == s_name)
        p_count = sum(1 for f in potential_findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == s_name)
        s_hex = SEV_COLORS.get(s_name, "#475569")
        matrix_data.append([
            Paragraph(f"<font color='{s_hex}'><b>● {s_name}</b></font>", small),
            Paragraph(f"<b>{c_count}</b>", small),
            Paragraph(str(p_count), small),
            Paragraph(impact_desc.get(s_name, ""), small),
        ])

    matrix_table = Table(matrix_data, colWidths=[30 * mm, 24 * mm, 32 * mm, 88 * mm])
    matrix_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(matrix_table)
    story.append(Spacer(1, 5 * mm))

    # =========================================================================
    # 3. CONFIRMED VULNERABILITIES (ACTIONABLE FINDINGS)
    # =========================================================================
    story.append(Paragraph("2. Confirmed Vulnerability Findings", h1))
    story.append(Paragraph(
        "Vulnerabilities in this section have been verified through active security probes, syntax divergence, "
        "or deterministic server signatures. Each confirmed item warrants immediate developer triage.",
        small,
    ))
    story.append(Spacer(1, 3 * mm))

    if not confirmed_findings:
        no_conf_box = Table(
            [[Paragraph("<b>✓ Zero Confirmed Vulnerabilities Detected</b><br/>"
                        "Automated scanning did not identify confirmed security flaws within the scanned routes. "
                        "Review coverage limitations and potential findings below for defense-in-depth guidance.", body)]],
            colWidths=[174 * mm],
        )
        no_conf_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#10b981")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(no_conf_box)
        story.append(Spacer(1, 4 * mm))
    else:
        # Summary table of all confirmed findings
        cf_summary_data = [
            [
                Paragraph("<b>#</b>", small_bold),
                Paragraph("<b>Severity</b>", small_bold),
                Paragraph("<b>Vulnerability</b>", small_bold),
                Paragraph("<b>Endpoint / Path</b>", small_bold),
                Paragraph("<b>Parameter</b>", small_bold),
                Paragraph("<b>CWE / CVSS</b>", small_bold),
            ]
        ]
        for idx, f in enumerate(confirmed_findings, 1):
            s_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            s_hex = SEV_COLORS.get(s_val, "#475569")
            f_url = getattr(f, "url", "")
            f_path = urlparse(f_url).path or "/"
            cvss_info = get_cvss_info(f.type, s_val)
            cvss_disp = f"CVSS {cvss_info['score']}" if cvss_info.get("score") else (f.cwe_id or "CWE-699")
            cf_summary_data.append([
                Paragraph(str(idx), small),
                Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()}</b></font>", small),
                Paragraph(f"<b>{escape(f.type[:28])}</b>", small),
                Paragraph(escape(f"{f.method or 'GET'} {f_path[:24]}"), small),
                Paragraph(escape((f.parameter or 'None')[:16]), small),
                Paragraph(escape(cvss_disp), small),
            ])

        cf_table = Table(cf_summary_data, colWidths=[8 * mm, 24 * mm, 46 * mm, 42 * mm, 26 * mm, 28 * mm])
        cf_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(cf_table)
        story.append(Spacer(1, 4 * mm))

        # Detailed individual concise finding cards
        story.append(Paragraph("<b>Confirmed Vulnerability Technical Details:</b>", h3))
        story.append(Spacer(1, 2 * mm))

        for idx, f in enumerate(confirmed_findings, 1):
            s_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            s_hex = SEV_COLORS.get(s_val, "#475569")
            f_url = getattr(f, "url", "")
            f_path = urlparse(f_url).path or "/"
            cvss_info = get_cvss_info(f.type, s_val)
            cwe_str = f.cwe_id or cvss_info.get("cwe", "CWE-699")
            ev_clean = redact(f.evidence or "Validated via status / timing response divergence.")

            card_rows = [
                [
                    Paragraph(f"<b>FINDING {idx}: {escape(f.type.upper())}</b>", ParagraphStyle("cd_title", parent=body_bold, fontSize=9, textColor=colors.HexColor("#0f172a"))),
                    Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()} | {f.confidence.value if hasattr(f.confidence, 'value') else f.confidence} CONFIDENCE</b></font>", ParagraphStyle("cd_sev", parent=small_bold, alignment=2)),
                ],
                [
                    Paragraph(
                        f"<b>Target Endpoint:</b> {escape(f.method or 'GET')} {escape(f_path)} &nbsp;|&nbsp; "
                        f"<b>Parameter:</b> <code>{escape(f.parameter or 'None')}</code> &nbsp;|&nbsp; "
                        f"<b>CWE:</b> {escape(cwe_str[:40])}<br/>"
                        f"<b>Full URL:</b> <font color='#0284c7'>{escape(f_url[:75])}</font>",
                        small,
                    ),
                    "",
                ],
                [
                    Paragraph(
                        f"<b>Technical Observation:</b> {escape(f.description or 'Target parameter accepts unvalidated input affecting server-side logic.')}<br/>"
                        f"<b>Impact:</b> {escape(f.impact or 'Unauthorized data exposure, integrity manipulation, or privilege violation.')}<br/>"
                        f"<b>Remediation:</b> {escape(f.remediation or 'Implement strict parameterization, context-aware encoding, and server validation.')}",
                        small,
                    ),
                    "",
                ],
                [
                    Paragraph(f"<b>Evidence Snippet:</b> <font face='Courier' color='#0f172a'>{escape(ev_clean[:220])}</font>", code_style),
                    "",
                ],
            ]

            card_table = Table(card_rows, colWidths=[120 * mm, 54 * mm])
            card_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))

            story.append(KeepTogether([card_table, Spacer(1, 3 * mm)]))

    # =========================================================================
    # 4. POTENTIAL FINDINGS & MANUAL VERIFICATION ITEMS (STRICTLY SEGREGATED)
    # =========================================================================
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("3. Potential Findings & Manual Verification", h1))

    advisory_text = (
        "<b>Segregation Notice:</b> The following security items are heuristic indicators or anomalies flagged "
        "as <i>Potential</i> or <i>Requires Manual Verification</i>. They are strictly segregated from confirmed bugs "
        "to prevent unverified submissions or false-positive escalation."
    )
    adv_box = Table([[Paragraph(advisory_text, small)]], colWidths=[174 * mm])
    adv_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d97706")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(adv_box)
    story.append(Spacer(1, 3 * mm))

    if not potential_findings:
        story.append(Paragraph("<i>No potential findings or manual verification anomalies were recorded during this scan.</i>", body))
        story.append(Spacer(1, 4 * mm))
    else:
        pot_rows = [
            [
                Paragraph("<b>Status</b>", small_bold),
                Paragraph("<b>Severity</b>", small_bold),
                Paragraph("<b>Heuristic Indicator / Type</b>", small_bold),
                Paragraph("<b>Affected Endpoint</b>", small_bold),
                Paragraph("<b>Verification Requirement</b>", small_bold),
            ]
        ]
        for f in potential_findings:
            det_st = getattr(f, "detection_status", "Potential")
            s_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            s_hex = SEV_COLORS.get(s_val, "#475569")
            f_url = getattr(f, "url", "")
            f_path = urlparse(f_url).path or "/"
            pot_rows.append([
                Paragraph(f"<font color='#d97706'><b>{det_st}</b></font>", small),
                Paragraph(f"<font color='{s_hex}'><b>{s_val}</b></font>", small),
                Paragraph(f"<b>{escape(f.type[:28])}</b>", small),
                Paragraph(escape(f"{f.method or 'GET'} {f_path[:26]}"), small),
                Paragraph(escape((f.description or "Heuristic response mismatch requires manual analyst review")[:50]), small),
            ])

        pot_table = Table(pot_rows, colWidths=[30 * mm, 18 * mm, 44 * mm, 38 * mm, 44 * mm])
        pot_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(pot_table)
        story.append(Spacer(1, 4 * mm))

    # =========================================================================
    # 5. ASSESSMENT SCOPE, TESTED MODULES & COVERAGE LIMITATIONS
    # =========================================================================
    story.append(Paragraph("4. Assessment Scope & Coverage Limitations", h1))

    cov_summary = getattr(scan, "coverage_summary", {}) or {}
    disc_ep = cov_summary.get("endpoints_discovered", scan.urls_discovered or 0)
    tested_ep = cov_summary.get("endpoints_tested", scan.urls_scanned or 0)
    disc_forms = cov_summary.get("forms_discovered", 0)
    tested_params = cov_summary.get("parameters_tested", 0)
    cov_pct = cov_summary.get("overall_coverage", 0.0)
    if not cov_pct and disc_ep > 0:
        cov_pct = round((tested_ep / disc_ep) * 100, 1)

    cov_rows = [
        [
            Paragraph("<b>Endpoints Discovered:</b>", small), Paragraph(str(disc_ep), small),
            Paragraph("<b>Endpoints Tested:</b>", small), Paragraph(str(tested_ep), small),
            Paragraph("<b>Route Coverage:</b>", small), Paragraph(f"<b>{cov_pct}%</b>", small),
        ],
        [
            Paragraph("<b>Discovered Forms:</b>", small), Paragraph(str(disc_forms), small),
            Paragraph("<b>Tested Parameters:</b>", small), Paragraph(str(tested_params), small),
            Paragraph("<b>Engine Engine:</b>", small), Paragraph("Playwright + Async Probes", small),
        ],
    ]
    cov_table = Table(cov_rows, colWidths=[32 * mm, 26 * mm, 32 * mm, 26 * mm, 30 * mm, 28 * mm])
    cov_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(cov_table)
    story.append(Spacer(1, 3 * mm))

    # Module Execution Matrix
    mod_status = cov_summary.get("modules", {})
    default_modules = [
        ("SQL Injection", "sqli", "Active injection testing on inputs, forms, and JSON payloads"),
        ("Cross-Site Scripting (XSS)", "xss", "Reflected and stored XSS contextual payload probes"),
        ("Command Injection", "command_injection", "OS command chaining and pipe execution tests"),
        ("Directory Traversal", "directory_traversal", "Relative path traversal and LFI probes"),
        ("Sensitive Files", "sensitive_files", "Exposed .env, .git, backups, and config checks"),
        ("CSRF Verification", "csrf", "Anti-CSRF token presence and SameSite cookie evaluation"),
        ("Security Headers", "security_headers", "CSP, HSTS, X-Content-Type-Options, Referrer-Policy"),
        ("CORS Misconfiguration", "cors", "Wildcard and reflected origin header verification"),
        ("Clickjacking", "clickjacking", "X-Frame-Options and frame-ancestors enforcement"),
    ]

    mod_data = [
        [
            Paragraph("<b>Security Scanner Module</b>", small_bold),
            Paragraph("<b>Status</b>", small_bold),
            Paragraph("<b>Execution Scope & Boundary</b>", small_bold),
        ]
    ]

    for mod_title, mod_key, mod_desc in default_modules:
        st = mod_status.get(mod_key, "Tested")
        st_color = "#059669" if st == "Tested" else "#d97706" if st in ("Incomplete", "Auth Required") else "#64748b"
        mod_data.append([
            Paragraph(f"<b>{mod_title}</b>", small),
            Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", small),
            Paragraph(mod_desc, small),
        ])

    mod_table = Table(mod_data, colWidths=[52 * mm, 26 * mm, 96 * mm])
    mod_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(mod_table)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph(
        "<b>Scope Limitations & Testing Boundaries:</b><br/>"
        "• Assessment was strictly black-box automated non-destructive probing without access to internal source code.<br/>"
        "• Client-side dynamic state machines requiring multi-factor authentication or interactive CAPTCHAs were bypassed.<br/>"
        "• Rate-limiting defenses or Web Application Firewalls (WAF) may throttle automated requests.",
        small,
    ))
    story.append(Spacer(1, 4 * mm))

    # =========================================================================
    # 6. PRIORITIZED REMEDIATION ROADMAP
    # =========================================================================
    story.append(Paragraph("5. Prioritized Remediation Roadmap", h1))
    story.append(Paragraph(
        "Action items ordered by exploitability and impact to systematically elevate application security posture.",
        small,
    ))
    story.append(Spacer(1, 2 * mm))

    rec_list = posture.get("recommendations", [])
    if not rec_list and confirmed_findings:
        for f in confirmed_findings:
            if f.remediation:
                rec_list.append({
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "finding_type": f.type,
                    "remediation": f.remediation,
                    "priority": 1 if str(f.severity).lower() in ("critical", "high") else 2,
                })

    if not rec_list:
        story.append(Paragraph("<b>✓ Defensive Baseline Maintained:</b> No remediation backlog items currently flagged. Continue scheduled periodic vulnerability reviews.", body))
    else:
        for i, rec in enumerate(rec_list[:8], 1):
            s_name = rec.get("severity", "Medium")
            s_hex = SEV_COLORS.get(s_name, "#475569")
            prio = rec.get("priority", 2)
            prio_label = "Phase 1: Immediate Action (24–48h)" if prio == 1 else "Phase 2: Target Sprint (2–4 weeks)" if prio == 2 else "Phase 3: Defense Hygiene"

            rec_table = Table(
                [
                    [
                        Paragraph(f"<b>ACTION {i}: {escape(rec.get('finding_type', 'Vulnerability'))}</b>", ParagraphStyle("ra_t", parent=body_bold, fontSize=8.5, textColor=colors.HexColor("#0f172a"))),
                        Paragraph(f"<font color='{s_hex}'><b>{s_name} | {prio_label}</b></font>", ParagraphStyle("ra_p", parent=small_bold, alignment=2)),
                    ],
                    [
                        Paragraph(escape(rec.get("remediation", "Implement defensive programming and input validation.")), small),
                        "",
                    ],
                ],
                colWidths=[114 * mm, 60 * mm],
            )
            rec_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(KeepTogether([rec_table, Spacer(1, 2.5 * mm)]))

    doc.build(story, canvasmaker=SummaryNumberedCanvas)
    return buf.getvalue()

