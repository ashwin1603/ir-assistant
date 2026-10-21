import math


def risk_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def compute_risk(severity: int, confidence: float, count: int) -> tuple[float, str]:
    frequency_factor = min(2.0, 1 + math.log2(count) / 4) if count > 0 else 1.0
    score = round(min(100.0, severity * 10 * confidence * frequency_factor), 1)
    return score, risk_level(score)
