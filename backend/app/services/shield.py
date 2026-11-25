"""Intelligent Shield: SMS preprocessing, deterministic rules and AI adapter.

The shield deliberately separates signal extraction from the risk engine. A future
model provider can implement ``AIClassifier`` without changing the API or the
rule explanations returned to clients.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from app.services.scoring import MessageIndicators, RiskResult, level_for

_URL_RE = re.compile(r"(?:https?|hxxp)://[^\s<>]+|www\.[^\s<>]+", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9']+")


@dataclass(frozen=True)
class PreprocessedMessage:
    original: str
    normalized: str
    tokens: tuple[str, ...]
    urls: tuple[str, ...]


@dataclass(frozen=True)
class RuleMatch:
    code: str
    label: str
    score: float
    explanation: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class AIClassification:
    label: str
    confidence: float
    explanation: str


@dataclass(frozen=True)
class ShieldAssessment:
    message: PreprocessedMessage
    rules: tuple[RuleMatch, ...]
    ai: AIClassification
    indicators: MessageIndicators
    signal_risk: RiskResult
    explanation: str

    @property
    def risk(self) -> RiskResult:
        """Backward-compatible pre-score; not a final product decision."""
        return self.signal_risk


class AIClassifier(Protocol):
    def classify(self, message: PreprocessedMessage, rules: tuple[RuleMatch, ...]) -> AIClassification:
        ...


def preprocess_sms(text: str) -> PreprocessedMessage:
    """Normalize Unicode/spacing while retaining the original message for audit."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.replace("\u200b", "").replace("\ufeff", "")
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    urls = tuple(_URL_RE.findall(normalized))
    tokens = tuple(_WORD_RE.findall(normalized))
    return PreprocessedMessage(original=text, normalized=normalized, tokens=tokens, urls=urls)


def _matches(message: PreprocessedMessage, patterns: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(pattern for pattern in patterns if re.search(pattern, message.normalized, re.IGNORECASE))


def _url_is_suspicious(url: str) -> bool:
    candidate = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        # Obfuscated domains such as ``example[.]com`` are common in scam
        # messages and must be treated as suspicious evidence, not parser
        # failures.
        return True
    host = (parsed.hostname or "").lower()
    return (
        parsed.scheme not in {"https"}
        or "@" in parsed.netloc
        or any(part in host for part in ("bit.ly", "tinyurl", "t.co", "goo.gl"))
        or host.replace(".", "").isdigit()
        or any(word in host for word in ("verify", "secure", "update", "login", "wallet", "bonus"))
    )


def detect_rules(message: PreprocessedMessage) -> tuple[RuleMatch, ...]:
    """Run explainable, conservative rules over a preprocessed SMS."""
    matches: list[RuleMatch] = []
    rule_specs = (
        (
            "credential_request", "credential request", 0.82,
            (r"(?:(?:\bpin\b|\bpassword\b|\bpasscode\b|\botp\b|\bone[- ]?time code\b|\bverification code\b).{0,55}(?:\bsend\b|\bshare\b|\btell\b|\bgive\b|\bconfirm\b|\bprovide\b|\benter\b|\bread\b)|(?:\bsend\b|\bshare\b|\btell\b|\bgive\b|\bconfirm\b|\bprovide\b|\benter\b|\bread\b).{0,55}(?:\bpin\b|\bpassword\b|\bpasscode\b|\botp\b|\bone[- ]?time code\b|\bverification code\b))",),
            "asks the recipient to disclose a secret or verification code",
        ),
        (
            "impersonation", "impersonation", 0.72,
            (r"\b(bank|mobile money|momo|police|court|tax|government|support|customer care|official)\b",),
            "uses an institution or authority identity",
        ),
        (
            "urgency", "urgency", 0.62,
            ((r"\b(urgent|urgently|immediately|now|today|quickly|within \d+ hours?|"
              r"last warning|account will be closed|act fast|limited slots?|"
              r"expires?(?: today)?|before \d+(?:am|pm)?)\b"),),
            "pressures the recipient to act quickly",
        ),
        (
            "payment_request", "payment request", 0.68,
            (r"\b(send|pay|transfer|deposit|cash[- ]?out|fee|charge)\b", r"\b(account|wallet|number|momo)\b"),
            "combines a payment action with an account or wallet reference",
        ),
    )
    for code, label, score, patterns, explanation in rule_specs:
        evidence = _matches(message, patterns)
        if len(evidence) == len(patterns):
            matches.append(RuleMatch(code, label, score, explanation, evidence))

    # These are common Ghanaian MoMo recovery scams.  Keep the transaction
    # alert itself neutral: a real alert and a fabricated alert can look the
    # same in text alone.  Escalate when the alert is paired with a reversal,
    # return-payment, or code request.
    normalized = message.normalized
    has_mistaken_transfer = bool(re.search(
        r"(?:mistaken(?:ly)?|by mistake|wrong(?:ly)?).{0,55}(?:sent|send|transfer|paid)|"
        r"(?:sent|send|transfer|paid).{0,55}(?:mistaken(?:ly)?|by mistake|wrong(?:ly)?)",
        normalized,
    ))
    asks_return_payment = bool(re.search(
        r"(?:send|pay|transfer|give|return).{0,35}(?:back|refund|reverse)|"
        r"(?:back|refund|reverse).{0,35}(?:to|send|pay|transfer)",
        normalized,
    ))
    negated_secret_warning = bool(re.search(
        r"(?:never|do not|don't|dont).{0,60}"
        r"(?:ask|share|send|give|tell|enter|provide).{0,45}"
        r"(?:pin|otp|password|passcode|verification code|code)|"
        r"(?:never|do not|don't|dont).{0,45}"
        r"(?:pin|otp|password|passcode|verification code|code)",
        normalized,
    ))
    user_refused_secret = bool(re.search(
        r"(?:i|we)\s+(?:did not|didn't|no|never)\s+"
        r"(?:give|share|send|tell|provide|enter|confirm)",
        normalized,
    ))
    has_reversal_context = bool(re.search(
        r"(?:reversal|reverse|cancel|unfreeze|unblock|blocked|frozen)",
        normalized,
    ))
    asks_reversal_code = bool(re.search(
        r"(?:read|tell|share|forward|give|send|enter|confirm).{0,35}"
        r"(?:reversal|reverse|cancel|verification|one[- ]?time|otp|code)|"
        r"(?:reversal|reverse|cancel|verification|one[- ]?time|otp|code).{0,35}"
        r"(?:read|tell|share|forward|give|send|enter|confirm)",
        normalized,
    )) and has_reversal_context and not negated_secret_warning
    has_transaction_alert = bool(re.search(
        r"(?:you have received|cash received|payment received|confirmed).{0,80}"
        r"(?:gh[₵c¢]|ghs|balance|transaction|from)",
        normalized,
    ))
    if has_mistaken_transfer and asks_return_payment:
        matches.append(RuleMatch(
            "wrong_transfer_recovery", "wrong-transfer recovery", 0.94,
            "claims a mistaken transfer and asks for money to be returned",
            ("mistaken transfer", "return payment"),
        ))
    if asks_reversal_code and re.search(r"(?:reversal|reverse|cancel|otp|code)", normalized):
        matches.append(RuleMatch(
            "reversal_code_request", "reversal-code request", 0.98,
            "asks for a code or secret to reverse, cancel, or unblock a transaction",
            ("reversal or verification code", "code disclosure action"),
        ))
    if has_transaction_alert and (asks_return_payment or asks_reversal_code):
        matches.append(RuleMatch(
            "fake_transaction_alert", "transaction-alert reversal", 0.92,
            "pairs a claimed payment alert with a request to reverse or return funds",
            ("transaction alert", "reversal or return request"),
        ))
    if has_transaction_alert and re.search(
        r"(?:reverse|reversal|mistake|wrong).{0,70}(?:code|call|send|pay|return)|"
        r"(?:call|code).{0,45}(?:reverse|reversal|mistake|wrong)", normalized,
    ):
        matches.append(RuleMatch(
            "wrong_transfer_recovery", "wrong-transfer recovery", 0.94,
            "pairs a transaction alert with a reversal, mistake, or code story",
            ("transaction alert", "reversal story"),
        ))

    # Ghanaian fake-deposit messages imitate a cash-in notification. Text
    # alone cannot prove that a payment is fabricated, so require an unusual
    # cash-in/reference cue without an identified provider before escalating.
    unbranded_cash_in = bool(re.search(
        r"(?:cash\s+in|reference\s*:\s*(?:cash\s+in|mistake))",
        normalized,
    )) and not re.search(r"\b(?:mtn|telecel|airteltigo|vodafone)\b", normalized)
    personal_sender_claim = bool(re.search(
        r"(?:sent from personal|not mtn|call me to reverse|reference\s*:\s*mistake)",
        normalized,
    ))
    if (unbranded_cash_in or personal_sender_claim) and has_transaction_alert:
        matches.append(RuleMatch(
            "fake_deposit_alert", "fake deposit alert", 0.86,
            "transaction notification has unbranded or personal-sender cues that require independent balance verification",
            ("cash-in or transaction notice", "unverified sender or reference"),
        ))

    # A brand name in a genuine transaction notification is not, by itself,
    # impersonation. Require an identity claim or a suspicious action paired
    # with the institution reference. This prevents ordinary family transfers,
    # balance notifications, and provider safety advisories from escalating.
    has_institution_claim = bool(re.search(
        r"(?:i am|we are|calling from|this is|representing|customer care|"
        r"support team|your account|will be blocked|will be closed|"
        r"verify|unblock|deactivate|deactivated)",
        normalized,
    ))
    has_suspicious_institution_action = bool(re.search(
        r"(?:pin|otp|password|passcode|verification code|fee|pay|"
        r"blocked|closed|deactivate|verify)",
        normalized,
    ))
    if any(rule.code == "impersonation" for rule in matches) and not (
        has_institution_claim
        or (has_suspicious_institution_action and any(
            rule.code in {"credential_request", "urgency", "suspicious_link",
                          "wrong_transfer_recovery", "reversal_code_request"}
            for rule in matches
        ))
    ):
        matches = [rule for rule in matches if rule.code != "impersonation"]

    provider_safety_advisory = bool(re.search(
        r"(?:never ask|do not share|don't share|do not approve|"
        r"report fraud|no customer is ever asked)",
        normalized,
    ))
    if provider_safety_advisory:
        matches = [rule for rule in matches if rule.code not in {
            "impersonation", "payment_request",
        }]
    if negated_secret_warning or user_refused_secret:
        matches = [rule for rule in matches if rule.code not in {
            "credential_request", "reversal_code_request", "impersonation",
        }]

    # “I sent money” and “please send money” are different signals. Only treat
    # payment language as a request when the message directs the recipient to
    # act, or when an already suspicious rule supplies that context.
    directed_payment = bool(re.search(
        r"(?:please|pls|abeg|kindly|send me|send it|send .*\bto\b|"
        r"pay .*\bto\b|transfer .*\bto\b|processing fee|insurance fee|"
        r"registration fee|send .*\bback\b)",
        normalized,
    ))
    transaction_notice = bool(re.search(
        r"(?:transaction|withdrawal|payment)\s+(?:of|was|is)|"
        r"(?:you have received|cash received|payment received|new balance|"
        r"check your momo|check your balance|i send .* for)",
        normalized,
    ))
    if any(rule.code == "payment_request" for rule in matches) and not (
        directed_payment or asks_return_payment or has_reversal_context
        or not transaction_notice
    ):
        matches = [rule for rule in matches if rule.code != "payment_request"]

    # Category-specific social-engineering signals. These require multiple
    # cues so that a harmless mention of a loan, WhatsApp, family, or SIM does
    # not become a fraud verdict by itself.
    has_fee_or_deposit = bool(re.search(
        r"(?:processing|registration|insurance|dispatch|customs|tax|deposit)"
        r"\s+(?:fee|charge|payment)|pay\s+gh|deposit\s+gh|"
        r"(?:loan|prize|scholarship).{0,45}(?:insurance|form|registration)",
        normalized,
    ))
    has_financial_offer = bool(re.search(
        r"(?:loan|prize|promo|promotion|grant|investment|profit|job|"
        r"employed|salary|guaranteed|winner|won|approved)",
        normalized,
    ))
    if has_financial_offer and (has_fee_or_deposit or any(
        rule.code in {"urgency", "suspicious_link", "payment_request"}
        for rule in matches
    )):
        matches.append(RuleMatch(
            "advance_fee_or_opportunity", "advance-fee or opportunity scam", 0.90,
            "offers money or an opportunity alongside a fee, urgency, or payment action",
            ("financial opportunity", "fee, urgency, or payment cue"),
        ))

    has_code_hijack_language = bool(re.search(
        r"(?:whatsapp|verification code|6[- ]digit code|six[- ]digit code|"
        r"logged out|forward (?:the|a) code|code .*mistake)",
        normalized,
    ))
    if has_code_hijack_language and any(re.search(
        pattern, normalized
    ) for pattern in (r"(?:forward|read|share|send|tell).{0,35}code", r"code.{0,35}(?:mistake|quickly|urgently|read|forward)")):
        matches.append(RuleMatch(
            "messaging_account_takeover", "messaging-account takeover", 0.94,
            "uses a messaging verification-code pretext to obtain account access",
            ("messaging account", "verification-code request"),
        ))

    has_family_or_authority_identity = bool(re.search(
        r"(?:mum|mom|mother|dad|father|brother|sister|cousin|auntie|uncle|"
        r"pastor|boyfriend|girlfriend|my love|friend)",
        normalized,
    ))
    has_emergency_or_new_number = bool(re.search(
        r"(?:accident|hospital|stranded|phone fell|lost my phone|new number|"
        r"temporary number|using a friend's phone|in trouble|customs)",
        normalized,
    ))
    if has_family_or_authority_identity and has_emergency_or_new_number and any(
        rule.code in {"payment_request", "urgency"} for rule in matches
    ):
        matches.append(RuleMatch(
            "emergency_impersonation_payment", "emergency impersonation payment", 0.90,
            "combines a familiar identity with an emergency or new-number payment story",
            ("familiar identity", "emergency or changed contact", "payment pressure"),
        ))

    has_sim_swap_language = bool(re.search(
        r"(?:sim\s*(?:swap|replacement|replace)|no service|network is gone|"
        r"replace your sim|sim has been deactivated|sim will be deactivated)",
        normalized,
    ))
    has_identity_secrets = bool(re.search(
        r"(?:ghana card|date of birth|pin|otp|verification code|account)",
        normalized,
    ))
    if has_sim_swap_language and has_identity_secrets:
        matches.append(RuleMatch(
            "sim_swap_account_takeover", "SIM-swap account takeover", 0.94,
            "links a SIM change or loss of service to identity or wallet secrets",
            ("SIM or service change", "identity or wallet secret"),
        ))

    blocked_account_language = bool(re.search(
        r"(?:\bblocked\b|\bbolck\w*\b|\blocked\b|\blockded\b|\bdeactivat(?:ed|e)\b|"
        r"account.{0,25}(?:expire|close|freeze|lock))", normalized,
    ))
    if blocked_account_language and re.search(
        r"(?:mtn|momo|telecom|agent report|wrong transaction|pin|pincode|code)", normalized,
    ):
        matches.append(RuleMatch(
            "account_blocking_impersonation", "account-blocking impersonation", 0.94,
            "uses an account restriction story with a mobile-money or verification cue",
            ("account restriction", "provider or secret cue"),
        ))

    compromised_wallet = bool(re.search(
        r"(?:lost network|network.*gone|pin.*reset|wallet.*emptied|account.*emptied)", normalized,
    )) and bool(re.search(r"(?:momo|wallet|account|sim|phone)", normalized))
    if compromised_wallet:
        matches.append(RuleMatch(
            "compromised_wallet", "compromised wallet report", 0.96,
            "reports a service or SIM change followed by wallet compromise",
            ("service or SIM change", "wallet loss or reset"),
        ))

    # These are high-frequency Ghanaian social-engineering categories that do
    # not always contain the literal words “scam”, “PIN”, or “urgent”.
    fake_job_language = bool(re.search(
        r"(?:part[- ]?time|work from home|online work|data collector|review products|"
        r"liking posts|earn ghs?\s*\d+\s*(?:daily|per day|/month)|no experience needed)",
        normalized,
    ))
    if fake_job_language and (re.search(r"(?:whatsapp|deposit|fee|pay|registration|uniform|unlock|start immediately)", normalized)):
        matches.append(RuleMatch(
            "fake_job_or_task", "fake job or task scam", 0.88,
            "promises easy work or earnings with a payment, deposit, or immediate-contact request",
            ("easy work or earnings", "payment or contact pressure"),
        ))

    romance_or_customs = bool(re.search(
        r"(?:soldier deployed|shipment.*(?:tema|customs|port)|customs wants|"
        r"dating[- ]app|online boyfriend|my love|build our future)", normalized,
    ))
    if romance_or_customs and re.search(r"(?:ghs?|money|send|pay|release|package|shipment)", normalized):
        matches.append(RuleMatch(
            "romance_or_customs_payment", "romance or customs-fee payment", 0.90,
            "relationship or parcel story is paired with a request for money",
            ("relationship or parcel pretext", "payment request"),
        ))

    money_mule = bool(re.search(
        r"(?:use your momo|use your number|receive (?:a )?payment|receive money).{0,80}"
        r"(?:client|account|give you \d+%|commission|percent)", normalized,
    ))
    if money_mule:
        matches.append(RuleMatch(
            "money_mule_recruitment", "money-mule recruitment", 0.88,
            "asks to use the recipient's wallet or number to receive money for a commission",
            ("use of another person's wallet", "commission or client pretext"),
        ))

    otp_social_engineering = bool(re.search(
        r"(?:received otp|otp for gh|code (?:came|sent).{0,35}(?:phone|mistake)|"
        r"someone called).{0,80}(?:share|read|forward|tell|give)", normalized,
    ))
    if otp_social_engineering:
        matches.append(RuleMatch(
            "otp_social_engineering", "OTP social engineering", 0.96,
            "an OTP or verification code is paired with a caller's request to disclose it",
            ("OTP received", "disclosure request"),
        ))

    attachment_takeover = bool(re.search(
        r"(?:payment receipt|receipt)[_.\w-]*\.(?:zip|apk|exe|html?)|"
        r"(?:reply|send).{0,30}(?:sms|verification)\s+code",
        normalized,
    ))
    if attachment_takeover:
        matches.append(RuleMatch(
            "malicious_attachment_or_code", "malicious attachment or code request", 0.90,
            "uses a suspicious attachment or group-verification code to continue an interaction",
            ("attachment or code pretext",),
        ))

    group_code_request = bool(re.search(
        r"(?:group|admin|member).{0,70}(?:sms|verification)?\s*code.{0,45}(?:reply|send|remain|removed)",
        normalized,
    ))
    if group_code_request:
        matches.append(RuleMatch(
            "messaging_account_takeover", "messaging-account takeover", 0.94,
            "threatens group access to obtain a verification code",
            ("group access threat", "code request"),
        ))

    twi_prize = bool(re.search(
        r"(?:wadi nkonim|promo no mu|fa ghs?\s*\d+\s*k[oɔ]|sika no ama wo)", normalized,
    )) and bool(re.search(r"(?:ghs?|momo|fa|pay|k[oɔ])", normalized))
    if twi_prize:
        matches.append(RuleMatch(
            "advance_fee_or_opportunity", "advance-fee or opportunity scam", 0.92,
            "uses a local-language prize or MoMo promotion with a payment cue",
            ("prize or promotion", "payment cue"),
        ))

    remote_access_financial = bool(re.search(
        r"(?:download|install).{0,45}(?:app|application).{0,70}(?:contacts|photos|sms|access)", normalized,
    )) and bool(re.search(r"(?:loan|money|paid|wallet|momo)", normalized))
    if remote_access_financial:
        matches.append(RuleMatch(
            "remote_access_financial", "remote-access financial scam", 0.90,
            "offers money while requesting an app with access to personal data or messages",
            ("financial offer", "contacts, photos, or SMS access"),
        ))

    investment_bait = bool(re.search(
        r"(?:invest|profit|return).{0,45}(?:ghs?|money|pay|telegram).{0,45}(?:24 hours|daily|weekly|slots)",
        normalized,
    ))
    if investment_bait:
        matches.append(RuleMatch(
            "investment_bait", "investment or profit bait", 0.88,
            "promises unusually fast returns alongside a payment or group-join request",
            ("fast returns", "payment or group request"),
        ))

    public_authority_data_request = bool(re.search(
        r"(?:hon\.? minister|government|allowance|leap|empowerment|24[- ]?hour economy)", normalized,
    )) and bool(re.search(r"(?:ghana card|momo number|pin|register|fill the form|link)", normalized))
    if public_authority_data_request:
        matches.append(RuleMatch(
            "government_data_harvest", "government data-harvest scam", 0.90,
            "uses a public-program or authority pretext to collect identity or wallet details",
            ("authority or public-program claim", "identity or wallet data request"),
        ))

    reported_loss = bool(re.search(
        r"(?:wallet balance is zero|wallet emptied|i did|i gave|already (?:shared|read|sent)|"
        r"they took my money)", normalized,
    )) and bool(re.search(r"(?:otp|code|pin|momo|wallet|money)", normalized))
    if reported_loss:
        matches.append(RuleMatch(
            "reported_account_loss", "reported account loss", 0.98,
            "message reports that a secret was shared or money was already lost",
            ("reported action", "account or money loss"),
        ))

    repeat_payment = bool(re.search(
        r"(?:already transferred|already paid|sent .* before).{0,90}(?:another|additional|more).{0,45}"
        r"(?:fee|insurance|tax|dispatch|payment)", normalized,
    ))
    if repeat_payment:
        matches.append(RuleMatch(
            "repeat_payment_after_transfer", "repeat-payment escalation", 0.88,
            "requests another fee after an earlier payment or transfer",
            ("earlier payment", "additional fee request"),
        ))

    twi_account_takeover = bool(re.search(
        r"(?:momo account|account).{0,45}(?:code|kyer[eɛ] me|show me|phone).{0,45}"
        r"(?:to|so|mu|no|now|ntɛm)", normalized,
    ))
    if twi_account_takeover and re.search(r"(?:code|account|phone)", normalized):
        matches.append(RuleMatch(
            "local_language_account_takeover", "local-language account takeover", 0.92,
            "uses a local-language account or code pretext to obtain a verification secret",
            ("account or code cue", "local-language request"),
        ))
    twi_pin_impersonation = bool(re.search(
        r"(?:mtn worker|meya|me yɛ|account no).{0,55}(?:pin|pincode|otp)", normalized,
    )) or bool(re.search(
        r"(?:account no).{0,55}(?:expire|blocked|lock|update).{0,35}(?:pin|otp)", normalized,
    ))
    if twi_pin_impersonation:
        matches.append(RuleMatch(
            "local_language_account_takeover", "local-language account takeover", 0.94,
            "uses a local-language provider or account pretext to request a wallet secret",
            ("provider or account pretext", "PIN or OTP cue"),
        ))

    twi_emergency_payment = bool(re.search(
        r"(?:mehia|ntɛm|mɛsan|network yɛ bɔne|mentumi nkasa).{0,100}"
        r"(?:ghs?|sika|number|momo|boa)", normalized,
    )) and bool(re.search(r"(?:ghs?|momo|number|fa k[oɔ])", normalized))
    if twi_emergency_payment:
        matches.append(RuleMatch(
            "emergency_impersonation_payment", "emergency impersonation payment", 0.92,
            "combines local-language distress or urgency with a mobile-money payment request",
            ("distress or urgency cue", "MoMo payment cue"),
        ))

    strong_payment_cue = bool(re.search(
        r"(?:don't tell|do not tell|keep this confidential|new number|"
        r"hospital|accident|customs|loan|prize|job|investment|"
        r"send .* urgently|pay .* immediately)",
        normalized,
    ))
    if any(rule.code == "payment_request" for rule in matches) and strong_payment_cue:
        matches.append(RuleMatch(
            "social_engineering_payment", "social-engineering payment", 0.86,
            "pairs a payment request with secrecy, emergency, or high-pressure context",
            ("payment request", "social-engineering cue"),
        ))

    # Legitimate provider advisories often mention PINs/OTPs specifically to
    # warn users not to share them.  Do not treat that negated warning as a
    # credential request.
    suspicious_urls = tuple(url for url in message.urls if _url_is_suspicious(url))
    if suspicious_urls:
        matches.append(RuleMatch(
            "suspicious_link", "suspicious link", 0.88,
            "contains a shortened, insecure or security-themed link",
            suspicious_urls,
        ))

    # Explicit safety advisories, OTP notifications, refusals, and ordinary
    # personal transfers must not be treated like the scam they describe.
    # These guards are deliberately applied after all rules are extracted.
    provider_advisory = bool(re.search(
        r"(?:never ask|never request|do not share|don't share|do not approve|"
        r"report fraud|no customer is ever asked|stay safe)", normalized,
    ))
    otp_notification = bool(re.search(
        r"(?:otp|one[- ]?time code).{0,80}(?:do not share|don't share|never share|"
        r"do not give|do not disclose|expires?)", normalized,
    )) and not bool(re.search(r"(?:asking|ask|share|read|forward|tell).{0,35}(?:otp|code)", normalized))
    refusal_or_report = bool(re.search(
        r"(?:i|we)\s+(?:did not|didn't|don['’]?t|no|never)\s+(?:give|share|send|tell|provide|enter)|"
        r"(?:no give|no share|i no give|i did not give)(?:.{0,40}(?:otp|code|pin))?|"
        r"(?:this number|they)\s+(?:say|said)\s+.*(?:ask|asked).*(?:otp|pin|code)",
        normalized,
    ))
    personal_transfer = bool(re.search(
        r"(?:bro|brother|sister|maame|mame|charley|chale|boss|friend|owe you|"
        r"waakye|chop money|transport sika|when i reach|send me the ghs)", normalized,
    )) and not bool(re.search(
        r"(?:urgent|immediately|now|fee|pin|otp|password|link|new number|"
        r"account.*blocked|account.*closed)", normalized,
    ))
    transaction_clarification = bool(re.search(
        r"(?:check|look at|see|confirm).{0,40}(?:momo|transaction|transfer|balance|history)|"
        r"(?:transfer|transaction).{0,40}(?:history|alert|arrived|come)", normalized,
    )) and not bool(re.search(r"(?:send|pay|give|share|enter|fee|urgent)", normalized))
    if provider_advisory or otp_notification:
        matches = [rule for rule in matches if rule.code not in {
            "credential_request", "impersonation", "payment_request", "urgency",
            "advance_fee_or_opportunity", "social_engineering_payment",
        }]
    if refusal_or_report:
        matches = [rule for rule in matches if rule.code not in {
            "credential_request", "impersonation", "otp_social_engineering",
        }]
    if personal_transfer or transaction_clarification:
        matches = [rule for rule in matches if rule.code not in {
            "payment_request", "impersonation", "urgency",
        }]
    return tuple(matches)


class HeuristicAIClassifier:
    """Deterministic local fallback with the same contract as a real AI model."""

    def classify(self, message: PreprocessedMessage, rules: tuple[RuleMatch, ...]) -> AIClassification:
        codes = {rule.code for rule in rules}
        if "credential_request" in codes and "impersonation" in codes:
            return AIClassification("account_takeover", 0.92, "credential request combined with institution impersonation")
        if "suspicious_link" in codes and ("urgency" in codes or "impersonation" in codes):
            return AIClassification("phishing", 0.90, "suspicious link combined with social-engineering language")
        if "payment_request" in codes and "urgency" in codes:
            return AIClassification("payment_scam", 0.86, "urgent payment request detected")
        if rules:
            confidence = min(0.84, 0.55 + 0.08 * len(rules))
            return AIClassification("suspicious", round(confidence, 4), "one or more scam-like patterns detected")
        return AIClassification("benign", 0.62, "no high-signal scam pattern detected")


def analyze_sms(text: str, *, classifier: AIClassifier | None = None) -> ShieldAssessment:
    if not text or not text.strip():
        raise ValueError("SMS text must not be empty")
    message = preprocess_sms(text)
    rules = detect_rules(message)
    ai = (classifier or HeuristicAIClassifier()).classify(message, rules)

    rule_score = max((rule.score for rule in rules), default=0.0)
    rule_average = sum(rule.score for rule in rules) / len(rules) if rules else 0.0
    link_score = max((rule.score for rule in rules if rule.code == "suspicious_link"), default=0.0)
    keyword_score = max((rule.score for rule in rules if rule.code in {
        "credential_request", "payment_request", "wrong_transfer_recovery",
        "reversal_code_request", "fake_transaction_alert",
    }), default=0.0)
    impersonation_score = max((rule.score for rule in rules if rule.code == "impersonation"), default=0.0)
    urgency_score = max((rule.score for rule in rules if rule.code == "urgency"), default=0.0)
    indicators = MessageIndicators(
        suspicious_keyword_score=round(keyword_score, 4),
        malicious_link_score=round(link_score, 4),
        impersonation_score=round(impersonation_score, 4),
        urgency_score=round(urgency_score, 4),
        indicator_count=len(rules),
    )
    # AI confidence is evidence, not an override. Combining it with rules keeps
    # the local fallback useful while remaining bounded and explainable.
    # A benign classification contributes confidence, not risk. Risk is driven
    # by observed indicators; otherwise ordinary messages would receive a
    # non-zero score merely because the classifier is confident they are benign.
    # This is a local evidence-strength signal for legacy consumers. Final
    # risk levels and interventions are produced only by risk_engine.assess.
    risk_score = min(1.0, 0.55 * rule_score + 0.25 * rule_average + 0.20 * ai.confidence) if rules else 0.0
    signal_risk = RiskResult(round(risk_score, 4), level_for(risk_score), round(min(1.0, ai.confidence), 4))
    reason_parts = [f"{rule.label}: {rule.explanation}" for rule in rules]
    explanation = f"AI classification: {ai.label} ({ai.confidence:.0%}). " + (" ".join(reason_parts) if reason_parts else ai.explanation + ".")
    return ShieldAssessment(message, rules, ai, indicators, signal_risk, explanation)
