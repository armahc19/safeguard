import pytest
from pydantic import ValidationError

from app.schemas.calls import CallAnalyzeRequest


def test_call_protection_requires_user_activation():
    with pytest.raises(ValidationError):
        CallAnalyzeRequest(caller_number="0241234567")


def test_call_transcript_requires_explicit_consent():
    with pytest.raises(ValidationError):
        CallAnalyzeRequest(
            caller_number="0241234567",
            user_activated_protection=True,
            transcript="The caller asked for my OTP.",
        )


def test_call_request_allows_consented_transcript():
    request = CallAnalyzeRequest(
        caller_number="0241234567",
        user_activated_protection=True,
        consented_transcript=True,
        transcript="The caller asked for my OTP.",
    )

    assert request.user_activated_protection is True
    assert request.consented_transcript is True
