"""Scoring engine: rule findings in, explainable verdict out.

The score is a plain sum of the weights of the rules that fired, with two
adjustments that exist to keep real-world mail from drowning in false positives:

* **Per-category caps.** Ten URL rules firing on one message says roughly the
  same thing as three firing, so each category's contribution is capped. Without
  this, a message with many links outscores a message with a forged sender.
* **Mitigations.** Full SPF/DKIM/DMARC alignment, or genuine bulk-mail headers,
  subtract from the total — a newsletter that trips the urgency and generic
  greeting rules should not land in the same band as a spoofed invoice.

Everything that moved the number is recorded in ``Analysis.score_breakdown`` so
the verdict can always be explained line by line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phishhawk.iocs import IOCSet, extract_iocs
from phishhawk.parser import ParsedEmail
from phishhawk.rules import (
    ALL_RULES,
    CATEGORY_ATTACHMENT,
    CATEGORY_AUTH,
    CATEGORY_CONTENT,
    CATEGORY_HEADER,
    CATEGORY_IDENTITY,
    CATEGORY_URL,
    CONTEXT_RULES,
    Finding,
    Rule,
)

CATEGORY_CAPS: dict[str, int] = {
    CATEGORY_AUTH: 34,
    CATEGORY_IDENTITY: 38,
    CATEGORY_URL: 46,
    CATEGORY_CONTENT: 42,
    CATEGORY_ATTACHMENT: 42,
    CATEGORY_HEADER: 20,
}

VERDICT_BANDS: list[tuple[int, str]] = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "SUSPICIOUS"),
    (15, "LOW"),
    (0, "BENIGN"),
]

VERDICT_ORDER = ["BENIGN", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]

# Rules serious enough that a message can never be called BENIGN when they fire,
# regardless of how many mitigations apply.
HARD_SIGNALS = frozenset({"ATT001", "ATT003", "URL002", "CONT005", "SEND004", "URL005"})


@dataclass
class Analysis:
    """The complete result of examining one message."""

    source: str = ""
    parsed: ParsedEmail | None = None
    iocs: IOCSet = field(default_factory=IOCSet)
    findings: list[Finding] = field(default_factory=list)
    context: list[Finding] = field(default_factory=list)
    score: int = 0
    raw_score: int = 0
    verdict: str = "BENIGN"
    score_breakdown: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    @property
    def mitre_techniques(self) -> list[str]:
        return sorted({f.mitre for f in self.findings if f.mitre})

    @property
    def categories(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for finding in self.findings:
            totals[finding.category] = totals.get(finding.category, 0) + finding.weight
        return totals

    @property
    def top_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.weight, reverse=True)

    def recommended_actions(self) -> list[str]:
        """Concrete next steps for whoever picks this message up."""
        actions: list[str] = []
        fired = {f.rule_id for f in self.findings}

        if self.verdict in ("CRITICAL", "HIGH"):
            actions.append("Quarantine the message and search the mail estate for other copies.")
            actions.append("Block the sender domain and the extracted URL domains at the gateway.")
        elif self.verdict == "SUSPICIOUS":
            actions.append("Hold for analyst review; confirm the request through a known-good channel.")
        elif self.verdict == "LOW":
            actions.append("No immediate action; keep the IOCs for correlation.")
        else:
            actions.append("No action required.")

        if fired & {"ATT001", "ATT002", "ATT003", "ATT005"}:
            actions.append("Detonate the attachment in a sandbox before any user opens it.")
        if fired & {"URL001", "URL002", "URL005", "URL011", "CONT005"}:
            actions.append("Submit the landing URLs to your URL sandbox and check proxy logs for visits.")
        if fired & {"CONT004", "CONT010", "SEND005"}:
            actions.append("Alert finance/AP: verify any payment or bank-detail change by phone using a number on file.")
        if fired & {"AUTH001", "AUTH002", "AUTH003"}:
            actions.append("Check whether the spoofed domain is yours; if so, review its DMARC policy enforcement.")
        if self.iocs.emails and self.verdict in ("CRITICAL", "HIGH", "SUSPICIOUS"):
            actions.append("Identify all recipients and check for credential submission or replies.")
        return actions

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "verdict": self.verdict,
            "score": self.score,
            "raw_score": self.raw_score,
            "email": self.parsed.to_dict() if self.parsed else {},
            "findings": [f.to_dict() for f in self.findings],
            "context": [f.to_dict() for f in self.context],
            "score_breakdown": self.score_breakdown,
            "mitigations": self.mitigations,
            "mitre_techniques": self.mitre_techniques,
            "iocs": self.iocs.to_dict(),
            "defanged_iocs": self.iocs.defanged(),
            "recommended_actions": self.recommended_actions(),
        }


def analyze(
    parsed: ParsedEmail,
    source: str = "",
    rules: list[Rule] | None = None,
    disabled: set[str] | None = None,
) -> Analysis:
    """Run every rule against ``parsed`` and score the result."""
    disabled = disabled or set()
    active = [r for r in (rules if rules is not None else ALL_RULES) if r.id not in disabled]

    iocs = extract_iocs(parsed)
    result = Analysis(source=source, parsed=parsed, iocs=iocs)

    for rule in active:
        if finding := rule.run(parsed, iocs):
            result.findings.append(finding)
    for rule in CONTEXT_RULES:
        if finding := rule.run(parsed, iocs):
            result.context.append(finding)

    _score(result)
    return result


def _score(result: Analysis) -> None:
    per_category: dict[str, list[Finding]] = {}
    for finding in result.findings:
        per_category.setdefault(finding.category, []).append(finding)

    total = 0
    for category, findings in sorted(per_category.items()):
        subtotal = sum(f.weight for f in findings)
        cap = CATEGORY_CAPS.get(category, 40)
        applied = min(subtotal, cap)
        total += applied
        note = f"{category}: {applied}"
        if applied < subtotal:
            note += f" (capped from {subtotal}, {len(findings)} rules)"
        else:
            note += f" ({len(findings)} rule{'s' if len(findings) != 1 else ''})"
        result.score_breakdown.append(note)

    result.raw_score = total
    total -= _apply_mitigations(result, total)
    result.score = max(0, min(100, total))
    result.verdict = _verdict_for(result)


def _apply_mitigations(result: Analysis, running_total: int) -> int:
    """Subtractions for signals that a message is genuine. Returns the deduction."""
    assert result.parsed is not None
    parsed = result.parsed
    auth = parsed.auth_results
    deduction = 0

    passing = [m for m in ("spf", "dkim", "dmarc") if auth.get(m) == "pass"]
    if len(passing) == 3:
        deduction += 14
        result.mitigations.append("-14  SPF, DKIM and DMARC all pass")
    elif "dmarc" in passing:
        deduction += 10
        result.mitigations.append("-10  DMARC passes (sender domain is aligned)")
    elif len(passing) == 2:
        deduction += 7
        result.mitigations.append(f"-7   {' and '.join(p.upper() for p in passing)} pass")
    elif len(passing) == 1:
        deduction += 3
        result.mitigations.append(f"-3   {passing[0].upper()} passes")

    if result.context and any(c.rule_id == "INFO001" for c in result.context):
        # Only credit bulk headers when the sender is actually authenticated —
        # otherwise a phisher just adds List-Unsubscribe to buy a discount.
        if passing:
            deduction += 8
            result.mitigations.append("-8   authenticated bulk-mail headers (List-Unsubscribe/List-Id)")

    fired = {f.rule_id for f in result.findings}
    if not fired & HARD_SIGNALS and running_total - deduction < 0:
        deduction = running_total
    return deduction


def _verdict_for(result: Analysis) -> str:
    fired = {f.rule_id for f in result.findings}
    verdict = next(name for threshold, name in VERDICT_BANDS if result.score >= threshold)
    if verdict == "BENIGN" and fired & HARD_SIGNALS:
        # A hard signal always warrants a human look, even if mitigations
        # dragged the arithmetic down.
        return "SUSPICIOUS"
    return verdict


def analyze_bytes(raw: bytes, source: str = "", disabled: set[str] | None = None) -> Analysis:
    """Convenience wrapper: parse raw bytes and analyze in one call."""
    from phishhawk.parser import parse_bytes

    return analyze(parse_bytes(raw), source=source, disabled=disabled)


def worse_of(a: str, b: str) -> str:
    """Return the more severe of two verdict names."""
    return a if VERDICT_ORDER.index(a) >= VERDICT_ORDER.index(b) else b
