from __future__ import annotations
import time
from typing import Dict, Any, Optional
import requests

class Sandbox:

    def __init__(self, api_key: Optional[str] = None):
        # Put your real key here or pass at construction
        self.api_key = api_key or "YOUR_HYBRID_ANALYSIS_KEY_HERE"

    def submit(self, file_path: str) -> Dict[str, Any]:

        # If no real key, keep old stub behavior
        if not self.api_key or self.api_key == "YOUR_HYBRID_ANALYSIS_KEY_HERE":
            return self._generate_stub_results(file_path)

        try:
            with open(file_path, "rb") as f:
                files = {"scan_file": f}
                resp = requests.post(
                    "https://www.hybrid-analysis.com/api/v2/submit/file",
                    files=files,
                    headers={
                        "api-key": self.api_key,
                        "user-agent": "phishdetect/1.0",
                    },
                    timeout=60,
                )
            if resp.status_code != 200:
                return {
                    "task_id": None,
                    "status": "error",
                    "http_status": resp.status_code,
                    "message": resp.text[:200],
                }
            data = resp.json()
            task_id = data.get("job_id") or data.get("task_id")
            return {
                "task_id": task_id,
                "status": "submitted",
                "report_url": f"https://www.hybrid-analysis.com/sample/{task_id}",
            }
        except Exception as e:
            return {
                "task_id": None,
                "status": "error",
                "error": str(e),
            }

    def _generate_stub_results(self, file_path: str) -> Dict[str, Any]:

        now = time.time()
        return {
            "task_id": f"stub-{int(now)}",
            "status": "completed",
            "verdict": "CLEAN",
            "analysis_url": "https://example.local/sandbox/stub",
            "extracted_strings": [file_path, "stub_result"],
            "timestamp": now,
        }
