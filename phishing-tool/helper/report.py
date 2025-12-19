from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from stix2 import Bundle, Indicator


def generate_json_report(
    meta_data: Dict[str, Any],
    iocs: Dict[str, List[str]],
    score: int = 72,
    verdict: str = "SUSPICIOUS",
    reasons: List[str] | None = None,
    raw_headers: str = "",
    output_path: str | Path = "threat_report.json",
) -> Tuple[Dict[str, Any], str]:

    if reasons is None:
        reasons = []

    report = {
        "meta": meta_data,
        "iocs": iocs,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "raw_headers": raw_headers,
    }

    json_path = str(output_path)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report, json_path

def generate_pdf_report(
    report_data: Dict[str, Any],
    output_path: str | Path = "threat_report.pdf",
) -> str:

    pdf_path = str(output_path)
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story: List[Any] = []

    # Title
    title = Paragraph("Threat Intelligence Report", styles["Title"])
    story.append(title)
    story.append(Spacer(1, 0.2 * inch))

    # Meta section
    meta = report_data.get("meta", {}) or {}
    meta_para = Paragraph(
        f"<b>Generated:</b> {meta.get('timestamp', 'N/A')}<br/>"
        f"<b>Verdict:</b> {report_data.get('verdict', 'N/A')} "
        f"(Score: {report_data.get('score', 0)}/100)",
        styles["Normal"],
    )
    story.append(meta_para)
    story.append(Spacer(1, 0.2 * inch))

    # Reasons
    reasons = report_data.get("reasons") or []
    if reasons:
        reasons_title = Paragraph("Reasons:", styles["Heading2"])
        story.append(reasons_title)
        for i, reason in enumerate(reasons, 1):
            story.append(Paragraph(f"{i}. {reason}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

    # IOCs
    iocs = report_data.get("iocs") or {}
    if iocs:
        iocs_title = Paragraph("Indicators of Compromise:", styles["Heading2"])
        story.append(iocs_title)
        for ioc_type, ioc_values in iocs.items():
            if not ioc_values:
                continue
            preview = ", ".join(ioc_values[:3])
            story.append(
                Paragraph(f"<b>{ioc_type.upper()}:</b> {preview}", styles["Normal"])
            )

    doc.build(story)
    return pdf_path

def generate_stix_bundle(
    iocs: Dict[str, List[str]],
    meta_data: Dict[str, Any],
    output_path: str | Path = "threat_report.stix",
) -> Tuple[Bundle, str]:

    objects: List[Any] = []

    for ioc_type, values in iocs.items():
        for value in values[:5]:
            if ioc_type == "ip_addresses":
                pattern = f"[ipv4-addr:value = '{value}']"
            elif ioc_type == "domains":
                pattern = f"[domain-name:value = '{value}']"
            else:
                pattern = f"[url:value = '{value}']"

            indicator = Indicator(
                type="indicator",
                name=f"{ioc_type}: {value}",
                pattern=pattern,
                pattern_type="stix",
                created=datetime.utcnow(),
                modified=datetime.utcnow(),
            )
            objects.append(indicator)

    bundle = Bundle(objects=objects)
    stix_json = bundle.serialize(pretty=True)

    stix_path = str(output_path)
    with open(stix_path, "w", encoding="utf-8") as f:
        f.write(stix_json)
    return bundle, stix_path