"""Conservative organisation-impersonation analysis.

This service evaluates claims such as "I am from the bank"; it does not
identify or accuse private individuals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class IdentityAnalysis:
    label: str
    claimed_identity: str | None
    identity_score: float
    confidence: float
    official_domain_match: bool | None
    reasons: tuple[str, ...]
    contradictions: tuple[str, ...]
    unknowns: tuple[str, ...]
    provenance: tuple[str, ...]

    def signals(self) -> dict[str, object]:
        return {
            "label": self.label,
            "claimed_identity": self.claimed_identity,
            "identity_score": self.identity_score,
            "confidence": self.confidence,
            "official_domain_match": self.official_domain_match,
            "reasons": list(self.reasons),
            "contradictions": list(self.contradictions),
            "unknowns": list(self.unknowns),
            "provenance": list(self.provenance),
        }


# These are domain families, not proof that a message is legitimate. Exact
# provider contact numbers should be supplied by a maintained registry later.
_OFFICIAL_DOMAINS = {
    "mtn.com.gh", "telecel.com.gh", "airteltigo.com.gh", "bog.gov.gh", "gov.gh",
}
_IDENTITY_ALIASES = (
    ("MTN Mobile Money", ("mtn", "mobile money", "momo")),
    ("Telecel", ("telecel", "vodafone")),
    ("AirtelTigo", ("airteltigo",)),
    ("Bank or financial institution", ("bank", "banking", "financial institution")),
    ("Government or public authority", ("police", "court", "tax", "government", "revenue authority")),
    ("Customer support", ("customer care", "customer support", "support team", "security team")),
)
_SECRET_RE = re.compile(r"\b(pin|otp|password|passcode|verification code|one[- ]?time code)\b", re.IGNORECASE)
_URGENCY_RE = re.compile(r"\b(urgent|immediately|now|last warning|account will be closed|act fast)\b", re.IGNORECASE)
_CLAIM_RE = re.compile(r"\b(i am|we are|calling from|representing|official|support|customer care)\b", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.IGNORECASE)
_SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl"}


def _bounded(value: float) -> float:
    return round(min(1.0, max(0.0, value)), 4)


def _host_is_official(host: str) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in _OFFICIAL_DOMAINS)


def assess_identity(text: str, *, phone_number: str | None = None) -> IdentityAnalysis:
    if not text or not text.strip():
        raise ValueError("Identity analysis text must not be empty")
    normalized = text.lower()
    claimed = next(
        (name for name, aliases in _IDENTITY_ALIASES if any(alias in normalized for alias in aliases)),
        None,
    )
    urls = _URL_RE.findall(normalized)
    official_match: bool | None = None
    if urls:
        hosts = [urlparse(url if "://" in url else f"https://{url}").hostname or "" for url in urls]
        official_match = any(_host_is_official(host) for host in hosts)

    reasons: list[str] = []
    contradictions: list[str] = []
    unknowns: list[str] = []
    score = 0.0
    if claimed and _CLAIM_RE.search(normalized):
        reasons.append(f"message claims to represent {claimed}")
        score += 0.18
    elif claimed:
        unknowns.append("organisation name appears without a clear identity claim")
    else:
        unknowns.append("no organisation or authority claim was identified")

    if _SECRET_RE.search(normalized):
        reasons.append("claimed service requests a PIN, OTP, password or verification code")
        score += 0.48
        if claimed:
            contradictions.append("legitimate support should not request a wallet secret")
    if _URGENCY_RE.search(normalized):
        reasons.append("identity claim is paired with urgency")
        score += 0.14
    if urls:
        if official_match:
            reasons.append("a referenced domain matches a configured official domain family")
            score -= 0.10
        else:
            reasons.append("referenced link does not match a configured official domain family")
            score += 0.22
            contradictions.append("claimed identity and link ownership do not align")
        if any((urlparse(url if "://" in url else f"https://{url}").hostname or "") in _SHORTENER_HOSTS for url in urls):
            reasons.append("identity claim uses a shortened link")
            score += 0.18
            contradictions.append("shortened links hide the destination identity")
    else:
        unknowns.append("no link was supplied for domain verification")

    if phone_number:
        unknowns.append("caller number has not been matched to a maintained official contact registry")
    else:
        unknowns.append("no phone number was supplied for contact verification")

    if not claimed:
        label = "no_identity_claim"
    elif score >= 0.55:
        label = "possible_impersonation"
    elif official_match:
        label = "official_reference_present"
    else:
        label = "unverified_identity_claim"
    confidence = _bounded(0.45 + 0.12 * len(reasons)) if claimed else 0.35
    return IdentityAnalysis(
        label=label, claimed_identity=claimed, identity_score=_bounded(score), confidence=confidence,
        official_domain_match=official_match, reasons=tuple(dict.fromkeys(reasons)),
        contradictions=tuple(dict.fromkeys(contradictions)), unknowns=tuple(dict.fromkeys(unknowns)),
        provenance=("identity_registry", "identity_language_rules"),
    )
