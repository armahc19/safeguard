"""Conservative, explainable identifier extraction for NEXUS report intake."""
from __future__ import annotations

import re

from app.core.exceptions import ValidationFailed
from app.core.phone import normalize_phone

_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_WALLET = re.compile(r"(?<![A-Za-z0-9])(?:0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
_GHANA_CARD = re.compile(r"\bGHA-\d{9}-\d\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{6,}\d)(?!\w)")
_LABELED_REFERENCE = re.compile(
    r"\b(?P<label>transaction|txn|account|wallet|momo|mobile\s+money|reference|ref|identity|customer|subscriber)"
    r"\s*(?:number|no\.?|id|reference)?\s*[:=#-]\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9./_-]{2,63})",
    re.IGNORECASE,
)
_LABELED_NAME = re.compile(
    r"\b(?P<label>suspect|victim|person|business|company|agent)(?:\s+name)?\s*[:=]\s*"
    r"(?P<value>[^\n,;]{2,80})",
    re.IGNORECASE,
)


def extract_report_identifiers(text: str, default_calling_code: str) -> list[dict[str, str | float]]:
    """Extract explicitly detectable values; callers store them as unverified evidence."""
    candidates: dict[tuple[str, str], dict[str, str | float]] = {}

    def add(kind: str, raw: str, confidence: float, *, normalized: str | None = None) -> None:
        value = raw.strip().strip(".,;:!?)]}>")
        if not value:
            return
        canonical = normalized or value.casefold()
        key = (kind, canonical)
        candidates.setdefault(key, {
            "kind": kind, "value": value, "normalized_value": canonical,
            "source_text": value, "confidence": confidence,
        })

    for match in _URL.finditer(text):
        add("link", match.group(0), 0.96)
    for match in _EMAIL.finditer(text):
        add("email", match.group(0), 0.96)
    for match in _WALLET.finditer(text):
        value = match.group(0)
        add("wallet", value, 0.98, normalized=value.lower() if value.startswith("0x") else value)
    for match in _GHANA_CARD.finditer(text):
        add("national_id", match.group(0), 0.96)
    for match in _LABELED_REFERENCE.finditer(text):
        label, value = match.group("label").casefold(), match.group("value")
        kind = "account" if label in {"account", "wallet", "momo", "mobile money"} else (
            "identity" if label in {"identity", "customer", "subscriber"} else "transaction")
        add(kind, value, 0.86)
    for match in _PHONE.finditer(text):
        value = match.group(0).strip()
        try:
            normalized = normalize_phone(value, default_calling_code)
        except ValidationFailed:
            continue
        add("phone", value, 0.94, normalized=normalized)
    for match in _LABELED_NAME.finditer(text):
        label, value = match.group("label").casefold(), match.group("value").strip().strip(". ")
        kind = "business" if label in {"business", "company"} else "agent" if label == "agent" else "person"
        add(kind, value, 0.72)

    return list(candidates.values())[:30]
