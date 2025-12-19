from __future__ import annotations
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Tuple, Dict, List

def parse_eml(path: str | Path) -> Tuple[Dict[str, str], List[str], str]:

    eml_path = Path(path)

    if not eml_path.is_file():
        raise FileNotFoundError(f"EML file not found: {eml_path}")

    with eml_path.open("rb") as file:
        msg: Message = BytesParser(policy=policy.default).parse(file)

    headers: Dict[str, str] = {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
    }

    received_list: List[str] = msg.get_all("Received", []) or []

    body = msg.get_body(preferencelist=("plain", "html"))
    body_text: str = body.get_content() if body else ""

    return headers, received_list, body_text

def format_email(path: str | Path) -> str:
    headers, received_list, body_text = parse_eml(path)

    lines: List[str] = ["--- Headers ---"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")

    lines.append("\n--- Received ---")
    lines.extend(received_list or ["<none>"])

    lines.append("\n--- Body-Text ---")
    lines.append(body_text or "<empty>")

    return "\n".join(lines)