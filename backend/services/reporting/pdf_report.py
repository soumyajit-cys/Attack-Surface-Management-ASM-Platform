from datetime import datetime, timezone, timedelta
from typing import Optional
from io import BytesIO

from sqlalchemy.orm import Session

from models import Finding, Asset, Organization, ScanHistory, Domain, Subdomain, Port, SSLResult, RiskScore, Alert
from utils.logger import logger


try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    logger.warning("fpdf2 not installed, PDF reports will not be available")


class PDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(37, 99, 235)
        self.cell(0, 10, "SentinelASM Security Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(37, 99, 235)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(37, 99, 235)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, text)
        self.ln(2)


def generate_executive_summary(
    db: Session,
    organization_id: int,
    asset_id: Optional[int] = None,
    since: Optional[datetime] = None,
) -> bytes:
    if not FPDF_AVAILABLE:
        raise RuntimeError("fpdf2 not installed. Install with: pip install fpdf2")

    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise ValueError("Organization not found")

    pdf.section_title("1. Executive Summary")

    assets_query = db.query(Asset).filter(Asset.organization_id == organization_id)
    if asset_id:
        assets_query = assets_query.filter(Asset.id == asset_id)
    assets = assets_query.all()

    findings_query = db.query(Finding).filter(Finding.organization_id == organization_id)
    if asset_id:
        findings_query = findings_query.filter(Finding.asset_id == asset_id)
    findings = findings_query.all()

    scans_query = db.query(ScanHistory).filter(ScanHistory.organization_id == organization_id)
    if asset_id:
        scans_query = scans_query.filter(ScanHistory.asset_id == asset_id)
    scans = scans_query.all()

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    info = sum(1 for f in findings if f.severity == "info")
    total_findings = len(findings)

    completed_scans = sum(1 for s in scans if s.status == "completed")
    failed_scans = sum(1 for s in scans if s.status == "failed")

    pdf.body_text(
        f"Organization: {org.name}\n"
        f"Report Period: {(datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')} to {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n"
        f"Assets Monitored: {len(assets)}\n"
        f"Total Findings: {total_findings} (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}, Info: {sum(1 for f in findings if f.severity == 'info')})\n"
        f"Scans Completed: {completed_scans}, Failed: {failed_scans}"
    )

    pdf.section_title("2. Risk Posture")

    risk_scores = db.query(RiskScore).join(Asset).filter(Asset.organization_id == organization_id).all()
    if risk_scores:
        avg_risk = sum(r.score for r in risk_scores) / len(risk_scores)
        max_risk = max(r.score for r in risk_scores)
        pdf.body_text(f"Average Asset Risk Score: {avg_risk:.1f}/10.0\nMaximum Asset Risk Score: {max_risk:.1f}/10.0")
    else:
        pdf.body_text("No risk scores available yet.")

    pdf.section_title("3. Top Findings by Severity")

    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        severity_findings = [f for f in findings if f.severity == severity]
        if not severity_findings:
            continue

        pdf.set_font("Helvetica", "B", 10)
        color_map = {
            "critical": (220, 38, 38),
            "high": (234, 88, 12),
            "medium": (245, 158, 11),
            "low": (16, 185, 129),
            "info": (107, 114, 128),
        }
        r, g, b = color_map.get(severity, (100, 100, 100))
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 6, f"{severity.upper()} ({len(severity_findings)} findings)", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)

        for finding in severity_findings[:5]:
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 5, f"  - {finding.title} ({asset.name if asset else 'Unknown'})", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    if len(findings) > 5:
        pdf.body_text(f"... and {len(findings) - 5} more findings")

    pdf.section_title("4. Asset Inventory")

    for asset in assets[:10]:
        asset_findings = [f for f in findings if f.asset_id == asset.id]
        asset_critical = sum(1 for f in asset_findings if f.severity == "critical")
        asset_high = sum(1 for f in asset_findings if f.severity == "high")

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"Asset: {asset.name} (Criticality: {asset.criticality})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"  Findings: {len(asset_findings)} total (Critical: {asset_critical}, High: {asset_high})", new_x="LMARGIN", new_y="NEXT")

        domains = db.query(Domain).filter(Domain.asset_id == asset.id).all()
        if domains:
            pdf.cell(0, 5, f"  Domains: {', '.join(d.domain for d in domains)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.section_title("5. Recent Scan Activity")

    recent_scans = sorted(scans, key=lambda s: s.started_at or datetime.min, reverse=True)[:10]
    for scan in recent_scans:
        status_color = {
            "completed": (16, 185, 129),
            "failed": (220, 38, 38),
            "running": (234, 88, 12),
            "pending": (107, 114, 128),
        }.get(scan.status, (100, 100, 100))

        pdf.set_text_color(*color_map.get(scan.status, (100, 100, 100)))
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"  {scan.target} - {scan.status.upper()} - {scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else 'N/A'}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)

    pdf.section_title("6. Recommendations")

    recommendations = [
        "Prioritize remediation of Critical and High severity findings.",
        "Implement missing security headers (CSP, HSTS, X-Frame-Options) across all web assets.",
        "Ensure all SSL/TLS certificates are valid and not expiring within 30 days.",
        "Close unnecessary open ports, especially critical ones (SSH, RDP, Database ports).",
        "Enable continuous monitoring with scheduled scans for all production assets.",
        "Configure alerting integrations (Slack, Discord, Email) for real-time notifications.",
        "Review and update asset criticality tags to reflect business impact.",
    ]

    for i, rec in enumerate(recommendations, 1):
        pdf.body_text(f"{i}. {rec}")

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 5, "This report was generated automatically by SentinelASM.", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, "For questions, contact your security team.", align="C", new_x="LMARGIN", new_y="NEXT")

    return pdf.output()


def generate_finding_detail_pdf(
    db: Session,
    finding_id: int,
) -> bytes:
    if not FPDF_AVAILABLE:
        raise RuntimeError("fpdf2 not installed. Install with: pip install fpdf2")

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise ValueError("Finding not found")

    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.section_title("Finding Detail Report")

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"Title: {finding.title}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)

    severity_color = {
        "critical": (220, 38, 38),
        "high": (234, 88, 12),
        "medium": (245, 158, 11),
        "low": (16, 185, 129),
        "info": (107, 114, 128),
    }.get(finding.severity.lower(), (100, 100, 100))

    pdf.set_text_color(*severity_color)
    pdf.cell(0, 6, f"Severity: {finding.severity.upper()}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)

    pdf.cell(0, 6, f"Category: {finding.category or 'N/A'}", new_x="LMARGIN", new_y="NEXT")

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
    if asset:
        pdf.cell(0, 6, f"Asset: {asset.name}", new_x="LMARGIN", new_y="NEXT")

    pdf.cell(0, 6, f"Created: {finding.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if finding.created_at else 'N/A'}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    pdf.section_title("Description")
    pdf.body_text(finding.description or "No description provided.")

    pdf.section_title("Recommendation")
    pdf.body_text(finding.recommendation or "No recommendation provided.")

    return pdf.output()