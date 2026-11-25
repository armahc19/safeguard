"""Phone number normalisation to E.164. Deliberately simple; swap in `phonenumbers` for full validation later."""
import re

from app.core.exceptions import ValidationFailed

_E164 = re.compile(r"^\+[1-9]\d{7,14}$")

# Small calling-code table; unknown codes map to "ZZ". Replace with `phonenumbers` for full coverage.
_CALLING_CODES = {
    "233": "GH", "234": "NG", "225": "CI", "228": "TG", "229": "BJ", "226": "BF", "221": "SN",
    "254": "KE", "255": "TZ", "256": "UG", "27": "ZA", "44": "GB", "1": "US", "91": "IN",
}


def country_for_e164(number: str) -> str:
    digits = number.lstrip("+")
    for length in (3, 2, 1):
        country = _CALLING_CODES.get(digits[:length])
        if country:
            return country
    return "ZZ"


def normalize_phone(raw: str, default_calling_code: str = "233") -> str:
    cleaned = re.sub(r"[\s\-().]", "", raw or "")
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    elif cleaned.startswith("+"):
        pass
    elif cleaned.startswith("0"):  # local format, e.g. 0241234567
        cleaned = "+" + default_calling_code + cleaned[1:]
    elif cleaned.startswith(default_calling_code):
        cleaned = "+" + cleaned
    else:
        raise ValidationFailed("Enter a valid phone number.", code="invalid_phone")

    if not _E164.match(cleaned):
        raise ValidationFailed("Enter a valid phone number.", code="invalid_phone")
    return cleaned
