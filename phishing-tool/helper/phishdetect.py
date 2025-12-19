#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.markdown import Markdown

from . Parser import Parser
from . import report, scorer, domain_tools, url_tools, attachments, sandbox, auth_checks
from . import phishdetect  # new orchestrator using async URL reputation + sandbox

console = Console()


class PhishDetectCLI:
    def __init__(self) -> None:
        self.name = "PHISHDETECT"
        self.version = "2.0"

    # ---------- Banner & Help ----------

    def print_banner(self) -> None:
        ascii_art = textwrap.dedent(f"""
        {self.name} v{self.version}
        ╔══════════════════════════════════════╗
        ║  Professional Phishing Detection     ║
        ║  Scan | Analyze | Batch | Report     ║
        ╚══════════════════════════════════════╝
        """).strip()
        console.print(Panel(ascii_art, title=self.name, border_style="bold cyan"))

    def print_help_markdown(self) -> None:
        help_text = textwrap.dedent("""
        # PHISHDETECT – Unified CLI

        ## Commands
        - `scan`        : Fast phishing scan of single email/text (local heuristics)
        - `analyze`     : Deep analysis (.eml + domains + URLs + sandbox)
        - `batch`       : Scan all .txt/.eml in directory
        - `report`      : Generate JSON/PDF/STIX report
        - `parse-eml`   : Parse & print .eml headers/body
        - `sandbox-test`: Run sandbox on content
        """)
        console.print(Markdown(help_text))

    # ---------- Helpers ----------

    def get_content(self, args) -> str:
        if getattr(args, "email", None):
            return args.email
        if getattr(args, "file", None):
            return Path(args.file).read_text(errors="ignore")
        if getattr(args, "text", None):
            return args.text
        raise ValueError("No content provided (use --email / --file / --text).")

    def detect_urgent_keywords(self, content: str) -> bool:
        urgent_words = ["urgent", "immediate", "critical", "emergency", "action required"]
        text = (content or "").lower()
        return any(w in text for w in urgent_words)

    def build_signals(
        self,
        content: str,
        sender: str,
        headers: Dict[str, str] | None = None,
    ) -> Dict[str, bool]:

        headers = headers or {}
        return {
            "knownbadurl": url_tools.is_known_bad_url(content),
            "dkimfail": auth_checks.check_dkim(headers),
            "frommismatch": bool(sender) and domain_tools.domain_mismatch(sender, content),
            "macrosinattachment": attachments.has_macros(content),
            "punycodedomain": domain_tools.has_punycode(content),
            "suspiciousurlshortener": url_tools.is_url_shortener(content),
            "mismatchurldisplay": getattr(url_tools, "url_display_mismatch", lambda _t: False)(content),
            "urgentlanguage": self.detect_urgent_keywords(content),
            "unexpectedattachment": attachments.unexpected_attachment(content),
        }

    def score_with_scorer(self, signals: Dict[str, bool]) -> Dict[str, Any]:

        result = scorer.score_message(signals)
        is_phishing = result.verdict != "benign"
        risk_level = (
            "HIGH" if result.verdict == "malicious"
            else "MEDIUM" if result.verdict == "suspicious"
            else "LOW"
        )
        return {
            "score": result.score,
            "verdict": result.verdict,
            "top_reasons": result.top_reasons,
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "max_score": 100,
        }

    def show_issues(self, issues: List[str]) -> None:
        if not issues:
            return
        console.print("[bold yellow]ISSUES DETECTED:[/bold yellow]")
        for i, issue in enumerate(issues, 1):
            console.print(f"  {i:2d}. [red]{issue}[/red]")

    def display_results(self, result: Dict[str, Any], title: str) -> None:
        status_emoji = "🔔 PHISH!" if result.get("is_phishing") else "✅ SAFE"
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
            result.get("risk_level", "LOW"), "green"
        )
        console.print(f"[bold {color}]{title}[/bold {color}]")
        console.print(f"[bold]Status:[/bold] {status_emoji}")
        console.print(
            f"[bold]Score:[/bold] {result.get('score', 0)}/{result.get('max_score', 100)}"
        )
        console.print(
            f"[bold]Risk:[/bold] [bold {color}]{result.get('risk_level', 'LOW')}[/bold {color}]"
        )
        self.show_issues(result.get("top_reasons", []))

    # ---------- Commands ----------

    def cmd_scan(self, args) -> None:

        content = self.get_content(args)
        headers: Dict[str, str] = {}
        signals = self.build_signals(content, args.sender or "", headers)
        score_result = self.score_with_scorer(signals)
        self.display_results(score_result, "FAST SCAN")

    def cmd_analyze(self, args) -> None:

        result = phishdetect.analyze_email(args.file)

        signals = result.get("signals", {})
        verdict = result.get("verdict", "unknown").lower()
        risk_level = (
            "HIGH" if verdict == "malicious"
            else "MEDIUM" if verdict == "suspicious"
            else "LOW"
        )
        score_result = {
            "score": result.get("score", 0),
            "verdict": result.get("verdict", "unknown"),
            "top_reasons": result.get("top_reasons", []),
            "is_phishing": verdict != "benign",
            "risk_level": risk_level,
            "max_score": 100,
        }

        table = Table(title="DETAILED ANALYSIS", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Verdict", score_result["verdict"].upper())
        table.add_row("Score", str(score_result["score"]))
        table.add_row("Risk", score_result["risk_level"])
        table.add_row("Signals True", str(sum(1 for v in signals.values() if v)))
        console.print(table)
        self.show_issues(score_result["top_reasons"])

    def cmd_batch(self, args) -> None:

        directory = Path(args.directory)
        files = list(directory.glob("*.txt")) + list(directory.glob("*.eml"))
        results = []

        for fp in files:
            if fp.suffix.lower() == ".eml":
                res = phishdetect.analyze_email(str(fp))
                verdict = res.get("verdict", "unknown").lower()
                is_phishing = verdict != "benign"
                score = res.get("score", 0)
            else:
                content = fp.read_text(errors="ignore")
                signals = self.build_signals(content, "")
                score_res = self.score_with_scorer(signals)
                is_phishing = score_res["is_phishing"]
                score = score_res["score"]

            results.append(
                {
                    "file": fp.name,
                    "is_phishing": is_phishing,
                    "score": score,
                }
            )

        table = Table(title="BATCH RESULTS", box=box.DOUBLE)
        table.add_column("File", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Score", justify="right")
        for r in results:
            status = "PHISH" if r["is_phishing"] else "SAFE"
            table.add_row(r["file"], status, str(r["score"]))
        console.print(table)

    def cmd_report(self, args) -> None:
        if getattr(args, "file", None):
            p = Parser()
            headers, _, body_text = p.parse_eml(args.file)
            content = body_text
        else:
            content = self.get_content(args)

        meta = {
            "timestamp": datetime.now().isoformat(),
            "tool_version": self.version,
            "analysis_engine": "PhishDetectCLI",
        }
        iocs = {
            "domains": domain_tools.extract_domains(content) if content else [],
            "urls": url_tools.extract_urls(content) if content else [],
            "ip_addresses": [],
        }
        score_val = args.score if args.score is not None else 72
        verdict = args.verdict or "SUSPICIOUS"
        reasons = args.reasons or ["CLI report generation"]

        report_data, _ = report.generate_json_report(
            meta, iocs, score=score_val, verdict=verdict, reasons=reasons, raw_headers=""
        )
        report.generate_pdf_report(report_data)
        report.generate_stix_bundle(iocs, meta)
        console.print(
            "[green]Reports generated: threat_report.json, threat_report.pdf, threat_report.stix[/green]"
        )

    def cmd_parse_eml(self, args) -> None:
        p = Parser()
        output = p.format_email(args.file)
        print(output)

    def cmd_sandbox(self, args) -> None:
        content = self.get_content(args)
        result = sandbox.run_sandbox(content)
        console.print(result)

    # ---------- Dispatcher ----------

    def run(self, args, parser: argparse.ArgumentParser) -> None:
        if args.command == "scan":
            self.cmd_scan(args)
        elif args.command == "analyze":
            self.cmd_analyze(args)
        elif args.command == "batch":
            self.cmd_batch(args)
        elif args.command == "report":
            self.cmd_report(args)
        elif args.command == "parse-eml":
            self.cmd_parse_eml(args)
        elif args.command == "sandbox-test":
            self.cmd_sandbox(args)
        else:
            parser.print_help()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishdetect",
        description="Professional Phishing Detection Toolkit (single entry CLI)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser("scan", help="Fast phishing scan (heuristics only)")
    p_scan.add_argument("--email", "-e")
    p_scan.add_argument("--file", "-f")
    p_scan.add_argument("--text", "-t")
    p_scan.add_argument("--sender", "-s")

    p_an = sub.add_parser("analyze", help="Deep analysis (.eml + reputation APIs + sandbox)")
    p_an.add_argument("--file", "-f", required=True)
    p_an.add_argument("--sender", "-s")

    p_batch = sub.add_parser("batch", help="Batch scan directory (.txt/.eml)")
    p_batch.add_argument("directory")

    p_rep = sub.add_parser("report", help="Generate JSON/PDF/STIX report")
    p_rep.add_argument("--file", "-f", required=True)
    p_rep.add_argument("--score", type=int)
    p_rep.add_argument("--verdict")
    p_rep.add_argument("--reasons", nargs="*")

    p_parse = sub.add_parser("parse-eml", help="Parse and print .eml")
    p_parse.add_argument("file")

    p_sbox = sub.add_parser("sandbox-test", help="Run sandbox on content")
    p_sbox.add_argument("--email", "-e")
    p_sbox.add_argument("--file", "-f")
    p_sbox.add_argument("--text", "-t")

    return parser

def main() -> None:
    cli = PhishDetectCLI()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        cli.print_banner()
        cli.print_help_markdown()
        sys.exit(0)

    try:
        cli.run(args, parser)
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
