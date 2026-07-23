"""Shared risk-scoring policy for human and machine-readable reports."""

from typing import Any, Dict, Iterable


BASE_RISK = {
    "Critical": 85,
    "High": 65,
    "Medium": 35,
    "Low": 10,
    "Info": 0,
}
SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


def risk_rating(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Informational"


def calculate_risk_score(findings: Iterable[Dict[str, Any]]) -> int:
    """Calculate an aggregate score without downgrading the highest finding.

    The highest finding establishes the minimum environment rating. Additional
    findings add diminishing concentration risk, preventing large inventories
    of informational observations from dominating the result.
    """
    ordered = sorted(
        (BASE_RISK.get(str(item.get("severity", "Info")), 0) for item in findings),
        reverse=True,
    )
    if not ordered:
        return 0

    total = float(ordered[0])
    multipliers = (0.12, 0.08, 0.05, 0.03, 0.02)
    for index, value in enumerate(ordered[1:]):
        multiplier = multipliers[index] if index < len(multipliers) else 0.01
        total += value * multiplier
    return min(100, int(round(total)))


def calibrate_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Return analysis with a severity-consistent risk score and rating."""
    result = dict(analysis)
    findings = list(result.get("findings", []))
    score = calculate_risk_score(findings)
    result["risk_score"] = score
    result["risk_rating"] = risk_rating(score)
    result["risk_method"] = (
        "highest finding establishes the minimum rating; additional findings "
        "add diminishing concentration risk"
    )
    return result
