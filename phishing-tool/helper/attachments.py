from __future__ import annotations
import email
import hashlib
import os
from pathlib import Path
from typing import List, Dict, Any
from oletools.olevba import VBA_Parser

def extract_attachments_from_eml(
    file_path: str | Path,
    tmp_dir: str | Path = "/tmp",
) -> List[Dict[str, Any]]:

    eml_path = Path(file_path)
    tmp_path = Path(tmp_dir)

    results: List[Dict[str, Any]] = []

    with eml_path.open("rb") as f:
        msg = email.message_from_binary_file(f)

    for part in msg.walk():
        # Skip container parts
        if part.get_content_maintype() == "multipart":
            continue

        filename = part.get_filename()
        if not filename:
            continue

        data = part.get_payload(decode=True)
        if data is None:
            continue

        # Save attachment to tmp_dir
        tmp_path.mkdir(parents=True, exist_ok=True)
        attach_path = tmp_path / filename
        attach_path.write_bytes(data)

        # Compute SHA256 hash
        file_hash = hashlib.sha256(data).hexdigest()

        # Check for macros if it is an Office document
        has_macros_flag = False
        macro_analysis: List[str] = []

        if filename.lower().endswith((".doc", ".docx", ".xls", ".xlsm")):
            try:
                vba = VBA_Parser(str(attach_path))
            except Exception:
                vba = None

            if vba is not None:
                try:
                    if vba.detect_macros():
                        has_macros_flag = True
                        for _, _, _, analyzed_content in vba.analyze():
                            macro_analysis.append(str(analyzed_content))
                finally:
                    vba.close()

        results.append(
            {
                "filename": filename,
                "path": str(attach_path),
                "sha256": file_hash,
                "has_macros": has_macros_flag,
                "macro_analysis": macro_analysis,
            }
        )

    return results

def has_macros(content: str) -> bool:

    text = (content or "").lower()
    return "enable macros" in text or "macro-enabled" in text

def unexpected_attachment(content: str) -> bool:

    text = (content or "").lower()
    keywords = ["attachment", ".pdf", ".docm", ".xlsm"]
    return any(k in text for k in keywords)