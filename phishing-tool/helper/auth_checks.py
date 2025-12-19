from __future__ import annotations

import re
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Dict, Any, Optional


def read_email_from_file(filepath: str | Path) -> bytes:

    path = Path(filepath)

    if not path.is_file():
        raise FileNotFoundError(f"Email file not found at {path}")

    return path.read_bytes()

def analyze_email_headers(raw_email_data: bytes) -> Dict[str, Any]:

    msg = BytesParser(policy=default).parsebytes(raw_email_data)

    auth_results_header: Optional[str] = msg.get("Authentication-Results")
    auth_missing = not auth_results_header

    results: Dict[str, Any] = {
        "auth_missing": auth_missing,
        "Authentication-Results": auth_results_header if auth_results_header else "Absent",
        "From": msg.get("From"),
        "Return-Path": msg.get("Return-Path"),
        "Reply-To": msg.get("Reply-To"),
        "SPF_Result_Parsed": "N/A",
        "DKIM_Result_Parsed": "N/A",
        "DMARC_Result_Parsed": "N/A",
        "From_Domain": "N/A",
        "Return_Path_Domain": "N/A",
        "Reply_To_Domain": "N/A",
    }

    # Extract domains from addresses (very simple heuristic)
    for header_name_raw in ("From", "Return-Path", "Reply-To"):
        header_value = msg.get(header_name_raw)
        if not header_value:
            continue

        dict_key_domain = f"{header_name_raw.replace('-', '_')}_Domain"
        match = re.search(r"@([\w\-\.]+)>?$", header_value)
        if match:
            results[dict_key_domain] = match.group(1)

    # Parse outcome tokens from Authentication-Results if present
    if auth_results_header:
        parts = auth_results_header.lower().split(";")
        for item in parts:
            item = item.strip()
            if "spf=" in item:
                match = re.search(r"spf=(\w+)", item)
                if match:
                    results["SPF_Result_Parsed"] = match.group(1)
            if "dkim=" in item:
                match = re.search(r"dkim=(\w+)", item)
                if match:
                    results["DKIM_Result_Parsed"] = match.group(1)
            if "dmarc=" in item:
                match = re.search(r"dmarc=(\w+)", item)
                if match:
                    results["DMARC_Result_Parsed"] = match.group(1)

    return results

def check_dkim(headers: Dict[str, str]) -> bool:
    auth_header = headers.get("Authentication-Results") or ""
    return "dkim=fail" in auth_header.lower()