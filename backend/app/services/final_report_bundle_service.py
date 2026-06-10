"""Phase 12.1 — ZIP bundle for final investigation report exports."""

from __future__ import annotations

import io
import zipfile

from app.schemas.final_report_schema import FinalInvestigationReport
from app.services import final_report_pdf_service, final_report_service, report_safety_service

README_TEXT = """PrivacyTrace-NP Final Investigation Report Bundle
=================================================

Contents:
- final_investigation_report.pdf — formal PDF export
- final_investigation_report.html — HTML export
- final_investigation_report.json — structured JSON export
- evidence_summary.csv — evidence inventory (metadata only)

Privacy rules:
- No raw sensitive values are included (phones, tokens, keys, passwords, etc.).
- Only masked values and safe metadata appear in these files.
- Raw scanner payloads and raw log file contents are not bundled.

Investigation disclaimer:
- This bundle supports security investigation and handover.
- It does not prove blame, legal responsibility, or guaranteed remediation.
- Human review is required before closure decisions.
"""


def build_final_report_bundle(report: FinalInvestigationReport) -> bytes:
    pdf_bytes = final_report_pdf_service.render_final_report_pdf(report)
    html_text = final_report_service.render_final_report_html(report)
    json_text = final_report_service.final_report_to_json(report)
    csv_text = final_report_service.build_evidence_summary_csv(report)

    report_safety_service.validate_text_blob(pdf_bytes.decode("latin-1", errors="ignore"))
    report_safety_service.validate_text_blob(html_text)
    report_safety_service.validate_text_blob(json_text)
    report_safety_service.validate_text_blob(csv_text)
    report_safety_service.validate_text_blob(README_TEXT)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("final_investigation_report.pdf", pdf_bytes)
        zf.writestr("final_investigation_report.html", html_text)
        zf.writestr("final_investigation_report.json", json_text)
        zf.writestr("evidence_summary.csv", csv_text)
        zf.writestr("README.txt", README_TEXT)

    zip_bytes = buffer.getvalue()
    report_safety_service.validate_text_blob(zip_bytes.decode("latin-1", errors="ignore"))
    return zip_bytes
