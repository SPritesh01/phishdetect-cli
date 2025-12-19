from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ScoreResult:

    score: int
    verdict: str
    top_reasons: List[str]


# Mapping of signal name -> weight contribution to the score.
WEIGHTS: Dict[str, int] = {
    "knownbadurl": 50,
    "dkimfail": 20,
    "frommismatch": 20,
    "macrosinattachment": 30,
    "punycodedomain": 25,
    "suspiciousurlshortener": 15,
    "mismatchurldisplay": 20,
    "urgentlanguage": 10,
    "unexpectedattachment": 15,
}


def score_message(signals: Dict[str, bool]) -> ScoreResult:

    raw_score = 0
    reasons: List[str] = []

    for signal, active in signals.items():
        if active and signal in WEIGHTS:
            weight = WEIGHTS[signal]
            raw_score += weight
            reasons.append(f"{signal} (+{weight})")

    # Clamp to 0–100
    score = max(0, min(100, raw_score))

    if score < 30:
        verdict = "benign"
    elif score < 70:
        verdict = "suspicious"  # 30–69
    else:
        verdict = "malicious"

    top_reasons = reasons[:3]
    return ScoreResult(score=score, verdict=verdict, top_reasons=top_reasons)