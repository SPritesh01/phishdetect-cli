# PHISHDETECT – Email Phishing Analysis Toolkit

PHISHDETECT is a modular, CLI‑driven phishing email analysis toolkit built in Python.  
It focuses on explainable, rule‑based detection using multiple independent modules:

- Header and authentication analysis (SPF/DKIM/DMARC)
- Domain and URL reputation / lookalike checks
- Attachment and macro heuristics
- Simple sandbox stub for behavior-style signals
- Unified scoring and reporting (JSON, PDF, STIX)
- Single entry point via `phishdetect.py` / `phishdetect` command

The goal is to have a tool that is **developer‑friendly**, **transparent** in how it scores risk, and easy to extend with new modules.

---

## Features

- **Single CLI entrypoint**  
  All functionality is exposed through `cli.py` so you can run everything from one command.

- **Header & auth analysis**  
  Parses `.eml` files and inspects `Authentication-Results`, `From`, `Return-Path`, and `Reply-To` using `auth_checks.py`.

- **Domain intelligence**  
  - Extracts domains from URLs.
  - Detects punycode / IDN.
  - Detects lookalike / brand‑impersonation domains (edit‑distance based).
  - Flags mismatches between sender domain and linked domains.

- **URL analysis**  
  - Extracts URLs from email body or `.eml` HTML parts.
  - Local blocklist checks.
  - Short URL / URL shortener detection.

- **Attachment & macro hints**  
  - Text‑based heuristics for “enable macros”, “attachment”, risky extensions.
  - Optional static analysis of real attachments via `oletools` if you integrate `extract_attachments_from_eml`.

- **Scoring engine**  
  - Rule‑based scorer in `scorer.py`.
  - Combines signals into a 0–100 score.
  - Buckets verdicts into `benign`, `suspicious`, `malicious`.
  - Keeps top reasons for explainability.

- **Reporting**  
  - JSON report with meta, IOCs, score, verdict, reasons.
  - PDF report via ReportLab for human‑readable output.
  - STIX 2.x bundle for IoC sharing.

- **Sandbox stub**  
  - Simulated sandbox results to show how a real integration could look.
  - Easy to replace with an actual sandbox API later.

---

## Project Structure

.
├── phishdetect.py      # Main entrypoint (PHISHDETECT CLI)
├── Parser.py           # .eml parsing (headers + body)
├── report.py           # JSON / PDF / STIX reporting
├── scorer.py           # Rule-based scoring engine
├── domain_tools.py     # Domain extraction, punycode, lookalike detection
├── url_tools.py        # URL extraction + local reputation checks
├── attachments.py      # Attachment / macro heuristics
├── sandbox.py          # Sandbox class / stub results
├── auth_checks.py      # Header auth parsing (SPF/DKIM/DMARC-style)
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── LICENSE             # License information

---

## Installation

### 1. Clone the repository

git clone https://github.com/SPritesh01/phishdetect-cli.git
cd phishdetect-cli

### 2. Create and activate a virtual environment

python3 -m venv .venv
source .venv/bin/activate

### 3. Install dependencies

pip install -r requirements.txt

---

## Usage

You can run the tool directly via `python3 cli.py` or create a shortcut command `phishdetect`.

### Direct usage

python3 phishdetect.py --help
python3 phishdetect.py scan --file suspicious_sample.eml --sender security@paypa1.com

### Optional: `phishdetect` command

Add this line to your `~/.bashrc` (adjust path):

alias phishdetect='python3 /home/<user>/<path-to-repo>/phishdetect.py'


Reload:

source ~/.bashrc

Now you can run:

phishdetect -h
phishdetect scan --file suspicious_sample.eml --sender security@paypa1.com

---

## Commands

### 1. Quick scan

Fast, body‑focused heuristic scan.

phishdetect scan --file suspicious_sample.eml --sender security@paypa1.com

or
phishdetect scan --email "Click http://secure-paypa1.com/login/verify within 24 hours" --sender security@paypa1.com


### 2. Deep analysis

Parses `.eml` + runs all signals.

phishdetect analyze --file suspicious_sample.eml --sender security@paypa1.com

### 3. Batch scan

Scan all `.txt` and `.eml` in a directory.

phishdetect batch emails/


### 4. Reporting (JSON, PDF, STIX)

phishdetect report --file suspicious_sample.eml
--score 95
--verdict MALICIOUS
--reasons "Known bad domain" "Short URL" "Urgent language"

Outputs:

- `threat_report.json`
- `threat_report.pdf`
- `threat_report.stix`

### 5. Parse `.eml` for inspection

phishdetect parse-eml suspicious_sample.eml


### 6. Sandbox stub

phishdetect sandbox-test --file suspicious_sample.eml


---

## Configuration & Extensibility

- **Signals and weights** live in `scorer.py`. 
  You can tune weights or add new boolean signals (e.g. ML model output) without changing the CLI.

- **Domain / URL logic** lives in `domain_tools.py` and `url_tools.py`. 
  You can plug in external reputation services there.

- **Sandbox integration** can be upgraded by replacing the stub in `sandbox.py` with real API calls.

- **Reports** can be customized by editing `report.py` (PDF template, STIX structure, etc).

---

## Roadmap / Ideas

- Integrate real SPF/DKIM verification library.
- Add ML‑based model as an additional signal.
- Export results in more formats (CSV, HTML dashboard).
- Add unit tests and CI for module‑level functions.
- Docker image for easier deployment.

---

## Disclaimer

This toolkit is for **security research and defensive purposes**. 
Do not use it to send phishing or conduct unauthorized testing on systems you do not own or have explicit permission to assess.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
