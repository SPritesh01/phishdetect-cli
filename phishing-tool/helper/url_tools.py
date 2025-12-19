from __future__ import annotations
import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests


# -------------------------
# URL extraction
# -------------------------

_URL_REGEX = re.compile(r"https?://[^\s\"'>]+")


def extract_urls(text: str) -> List[str]:

    if not text:
        return []
    return _URL_REGEX.findall(text)


# -------------------------
# Local heuristics
# -------------------------

# Simple local domain blocklist (extend as needed)
_LOCAL_BLOCKLIST = {
    "login.microsoftonline.com-fake.com",
    "paypal-secure-login.net",
    "secure-update-paypal.com",
}

# Common URL shorteners often abused in phishing [web:120]
_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "is.gd",
    "cutt.ly",
}

def is_known_bad_url(url: str) -> bool:

    try:
        domain = urlparse(url).netloc.lower()
    except Exception:
        return False
    return any(bad in domain for bad in _LOCAL_BLOCKLIST)


def is_url_shortener(url: str) -> bool:

    try:
        domain = urlparse(url).netloc.lower()
    except Exception:
        return False
    return any(domain == s or domain.endswith("." + s) for s in _SHORTENERS)


# -------------------------
# External reputation APIs
# -------------------------

# Put your keys here (or inject via environment/config)
_ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY_HERE"      # https://www.abuseipdb.com/register [web:31]
_PHISHTANK_KEY = "YOUR_PHISHTANK_KEY_HERE"      # https://phishtank.net/api_info.php [web:125]
_GOOGLE_SAFEBROWSING_KEY = "YOUR_GOOGLE_API_KEY_HERE"  # https://developers.google.com/safe-browsing [web:28]


async def _run_in_executor(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

async def check_abuseipdb(domain: str) -> Dict[str, Any]:

    if not _ABUSEIPDB_KEY or _ABUSEIPDB_KEY == "YOUR_ABUSEIPDB_KEY_HERE":
        return {}

    try:
        def _request():
            return requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": domain, "maxAgeInDays": 90},
                headers={"Key": _ABUSEIPDB_KEY},
                timeout=10,
            )

        resp = await _run_in_executor(_request)
        data = resp.json()
        score = int(data["data"]["abuseConfidenceScore"])
        return {"malicious": score > 50, "confidence": score}
    except Exception:
        return {}


async def check_phishtank(url: str) -> Dict[str, Any]:
    if not _PHISHTANK_KEY or _PHISHTANK_KEY == "YOUR_PHISHTANK_KEY_HERE":
        return {}

    try:
        def _request():
            return requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": url,
                    "format": "json",
                    "app_key": _PHISHTANK_KEY,
                },
                timeout=10,
            )

        resp = await _run_in_executor(_request)
        data = resp.json()
        results = data.get("results", {})
        # 'valid' == 'y' and 'in_database' == true implies known phish [web:125]
        malicious = str(results.get("valid", "n")).lower() == "y"
        return {"malicious": malicious}
    except Exception:
        return {}


async def check_urlhaus(domain: str) -> Dict[str, Any]:

    try:
        def _request():
            return requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=10,
            )

        resp = await _run_in_executor(_request)
        data = resp.json()
        if data.get("query_status") != "ok":
            return {"malicious": False, "url_count": 0}
        urls = data.get("urls", []) or []
        return {"malicious": len(urls) > 0, "url_count": len(urls)}
    except Exception:
        return {}


async def check_safebrowsing(url: str) -> Dict[str, Any]:

    if not _GOOGLE_SAFEBROWSING_KEY or _GOOGLE_SAFEBROWSING_KEY == "YOUR_GOOGLE_API_KEY_HERE":
        return {}

    try:
        body = {
            "client": {"clientId": "phishdetect", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        def _request():
            return requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": _GOOGLE_SAFEBROWSING_KEY},
                json=body,
                timeout=10,
            )

        resp = await _run_in_executor(_request)
        data = resp.json()
        matches = data.get("matches", []) or []
        return {"malicious": len(matches) > 0, "threats": matches}
    except Exception:
        return {}

# -------------------------
# Unified reputation entrypoint
# -------------------------

async def check_url(url: str) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "reputation": "UNKNOWN",
        "score": 0,
        "local_blocklist": False,
        "shortener": False,
        "evidence": {},
    }

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    result["domain"] = domain

    # 1) Local checks
    if is_known_bad_url(url):
        result["local_blocklist"] = True
        result["reputation"] = "BLOCK"
        result["score"] = max(result["score"], 90)

    if is_url_shortener(url):
        result["shortener"] = True
        result["score"] += 10

    # 2) External reputation (async fan‑out)
    tasks = [
        check_abuseipdb(domain),
        check_phishtank(url),
        check_urlhaus(domain),
        check_safebrowsing(url),
    ]
    api_results = await asyncio.gather(*tasks, return_exceptions=True)

    abuse_res, phish_res, haus_res, safe_res = api_results

    # Normalize errors → {}
    abuse_res = {} if isinstance(abuse_res, Exception) else abuse_res
    phish_res = {} if isinstance(phish_res, Exception) else phish_res
    haus_res = {} if isinstance(haus_res, Exception) else haus_res
    safe_res = {} if isinstance(safe_res, Exception) else safe_res

    result["evidence"]["abuseipdb"] = abuse_res
    result["evidence"]["phishtank"] = phish_res
    result["evidence"]["urlhaus"] = haus_res
    result["evidence"]["safebrowsing"] = safe_res

    # Score contributions
    if abuse_res.get("malicious"):
        result["score"] += 40
    if phish_res.get("malicious"):
        result["score"] += 50
    if haus_res.get("malicious"):
        result["score"] += 30
    if safe_res.get("malicious"):
        result["score"] += 50

    # Clamp score
    result["score"] = max(0, min(100, result["score"]))

    # Final reputation label
    if result["score"] >= 70:
        result["reputation"] = "BLOCK"
    elif result["score"] >= 30:
        result["reputation"] = "SUSPICIOUS"
    else:
        if result["reputation"] != "BLOCK":  # from local blocklist
            result["reputation"] = "CLEAN"

    return result
