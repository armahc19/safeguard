"""Versioned, explainable fraud-pattern classification.

The model adapter is optional. A deterministic classifier keeps the API useful
when model artifacts or optional ML dependencies are unavailable.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from app.services.model_runtime import JoblibTextClassifier, unified_model_runtime
from app.services.shield import ShieldAssessment


@dataclass(frozen=True)
class PatternMatch:
    pattern_id: str
    name: str
    category: str
    probability: float
    selected: bool
    evidence: tuple[str, ...]
    counter_checks: tuple[str, ...]


@dataclass(frozen=True)
class PatternAnalysis:
    matches: tuple[PatternMatch, ...]
    model_version: str
    campaign_fingerprint: str
    hazard: float
    reasons: tuple[str, ...]

    @property
    def selected(self) -> tuple[PatternMatch, ...]:
        return tuple(match for match in self.matches if match.selected)


class PatternClassifier(Protocol):
    version: str

    def predict(self, text: str) -> dict[str, float]:
        ...


_PATTERNS = {
    "FP001": {
        "name": "Fabricated credit and refund pretext",
        "category": "false_transaction_story",
        "terms": ("refund", "mistaken", "sent by mistake", "reverse payment"),
        "evidence": "a refund or mistaken-payment story is present",
        "counter": "check the official balance and transaction history independently",
    },
    "FP002": {
        "name": "Provider or staff impersonation",
        "category": "impersonation",
        "terms": ("bank", "mobile money", "momo", "support", "customer care", "official"),
        "evidence": "an institution or support identity is claimed",
        "counter": "contact the provider through an independently obtained official channel",
    },
    "FP003": {
        "name": "Account blocking or unblocking pretext",
        "category": "threat_and_reassurance",
        "terms": ("blocked", "blocking", "unblock", "suspend", "will close"),
        "evidence": "account restriction or closure language is present",
        "counter": "verify account status directly in the official app or provider channel",
    },
    "FP004": {
        "name": "Reward, prize or opportunity bait",
        "category": "reward_bait",
        "terms": ("prize", "reward", "bonus", "promotion", "loan", "investment"),
        "evidence": "an unexpected reward or financial opportunity is offered",
        "counter": "verify promotions through official sources before acting",
    },
    "FP005": {
        "name": "Credential harvesting under service or verification pretext",
        "category": "credential_theft",
        "terms": ("pin", "otp", "password", "passcode", "verification code"),
        "evidence": "a wallet secret or verification code is requested",
        "counter": "never share a wallet PIN or OTP",
    },
    "FP006": {
        "name": "Recipient or destination substitution",
        "category": "payment_redirection",
        "terms": ("new number", "different number", "send it to", "changed number"),
        "evidence": "the payment destination appears to have changed",
        "counter": "confirm the destination with the intended recipient through a known channel",
    },
}


class HeuristicPatternClassifier:
    version = "heuristic-patterns-1"

    def predict(self, text: str) -> dict[str, float]:
        normalized = text.lower()
        scores: dict[str, float] = {}
        for pattern_id, spec in _PATTERNS.items():
            count = sum(1 for term in spec["terms"] if term in normalized)
            if count:
                scores[pattern_id] = round(min(0.95, 0.55 + 0.12 * (count - 1)), 4)
        return scores


class JoblibPatternClassifier(JoblibTextClassifier):
    """Backward-compatible name for the shared model-runtime adapter."""

    def __init__(self, path: str, threshold: float = 0.5) -> None:
        super().__init__(model_name="pattern", path=path, threshold=threshold)

    def predict(self, text: str) -> dict[str, float]:
        return self.predict_result(text).scores

    def predict_result(self, text: str):
        return super().predict(text)


class RuntimePatternClassifier:
    """Pattern-service view over the shared runtime's loaded artifact."""

    @property
    def version(self) -> str:
        return unified_model_runtime.pattern_classifier.version

    def predict(self, text: str) -> dict[str, float]:
        return unified_model_runtime.pattern_classifier.predict(text).scores


def _default_model() -> PatternClassifier:
    model = unified_model_runtime.pattern_classifier
    if model.available:
        return RuntimePatternClassifier()
    return HeuristicPatternClassifier()


def _fingerprint(text: str, selected: tuple[PatternMatch, ...]) -> str:
    tokens = sorted(set(re.findall(r"[a-z0-9]+", text.lower())))
    labels = sorted(match.pattern_id for match in selected)
    payload = json.dumps({"tokens": tokens, "patterns": labels}, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def analyze_patterns(
    text: str,
    shield: ShieldAssessment | None = None,
    *,
    classifier: PatternClassifier | None = None,
    threshold: float = 0.5,
) -> PatternAnalysis:
    if not text or not text.strip():
        raise ValueError("Pattern analysis text must not be empty")
    normalized = text.strip().lower()
    classifier = classifier or _default_model()
    model_scores = classifier.predict(normalized)
    heuristic_scores = HeuristicPatternClassifier().predict(normalized)
    scores = {pattern_id: max(model_scores.get(pattern_id, 0.0), score)
              for pattern_id, score in heuristic_scores.items() | model_scores.items()}
    if shield:
        if any(rule.code == "credential_request" for rule in shield.rules):
            scores["FP005"] = max(scores.get("FP005", 0.0), 0.9)
        if any(rule.code == "impersonation" for rule in shield.rules):
            scores["FP002"] = max(scores.get("FP002", 0.0), 0.8)
        if any(rule.code == "urgency" for rule in shield.rules):
            scores["FP003"] = max(scores.get("FP003", 0.0), 0.6)

    # The taxonomy model sees words such as “OTP”, “MoMo”, and “promo” even
    # when a provider is warning users not to share them. Remove generic
    # taxonomy matches for those explicit benign contexts; high-specificity
    # shield rules remain the authoritative evidence for escalation.
    provider_advisory = bool(re.search(
        r"(?:never ask|never request|do not share|don't share|do not approve|"
        r"report fraud|no customer is ever asked|stay safe)", normalized,
    ))
    otp_notification = bool(re.search(
        r"(?:otp|one[- ]?time code).{0,80}(?:do not share|don't share|never share|"
        r"do not give|do not disclose|expires?)", normalized,
    )) and not bool(re.search(r"(?:asking|ask|share|read|forward|tell).{0,35}(?:otp|code)", normalized))
    personal_transfer = bool(re.search(
        r"(?:bro|brother|sister|maame|mame|charley|chale|boss|friend|owe you|"
        r"waakye|chop money|transport sika|when i reach|send me the ghs)", normalized,
    )) and not bool(re.search(r"(?:urgent|immediately|fee|pin|otp|password|link|new number)", normalized))
    transaction_clarification = bool(re.search(
        r"(?:check|look at|see|confirm).{0,40}(?:momo|transaction|transfer|balance|history)|"
        r"(?:transfer|transaction).{0,40}(?:history|alert|arrived|come)", normalized,
    )) and not bool(re.search(r"(?:send|pay|give|share|enter|fee|urgent)", normalized))
    refusal_or_report = bool(re.search(
        r"(?:no give|no share|i no give|i did not give|did not give|didn't give)", normalized,
    ))
    if provider_advisory or otp_notification:
        scores = {key: value for key, value in scores.items() if key not in {"FP002", "FP004", "FP005"}}
    if personal_transfer or transaction_clarification:
        scores = {key: value for key, value in scores.items() if key not in {"FP002", "FP005"}}
    if refusal_or_report:
        scores = {key: value for key, value in scores.items() if key not in {"FP002", "FP005"}}

    matches: list[PatternMatch] = []
    for pattern_id, probability in sorted(scores.items(), key=lambda item: item[1], reverse=True):
        spec = _PATTERNS.get(pattern_id)
        if spec is None:
            continue
        selected = probability >= threshold
        matches.append(PatternMatch(
            pattern_id=pattern_id, name=spec["name"], category=spec["category"],
            probability=round(probability, 4), selected=selected,
            evidence=(spec["evidence"],) if selected else (),
            counter_checks=(spec["counter"],) if selected else (),
        ))
    selected = tuple(match for match in matches if match.selected)
    reasons = tuple(f"pattern: {match.name}" for match in selected)
    hazard = round(min(0.6, sum(match.probability * 0.18 for match in selected)), 4)
    return PatternAnalysis(
        matches=tuple(matches), model_version=classifier.version,
        campaign_fingerprint=_fingerprint(normalized, selected), hazard=hazard, reasons=reasons,
    )
