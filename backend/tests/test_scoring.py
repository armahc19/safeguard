import pytest

from app.enums import RiskLevel
from app.services import scoring
from app.services.scoring import (
    MessageIndicators,
    PhoneReputation,
    TransactionContext,
    assess_risk,
    combine,
    level_for,
    score_reports,
    short_message,
)


def test_no_reports_is_low_with_no_confidence():
    r = score_reports(0, 0)
    assert (r.score, r.level, r.confidence) == (0.0, RiskLevel.LOW, 0.0)


@pytest.mark.parametrize("verified, pending, level", [
    (1, 0, RiskLevel.MEDIUM),
    (2, 0, RiskLevel.HIGH),
    (3, 0, RiskLevel.CRITICAL),
    (0, 1, RiskLevel.LOW),
    (0, 3, RiskLevel.MEDIUM),
    (0, 6, RiskLevel.HIGH),
])
def test_levels(verified, pending, level):
    assert score_reports(verified, pending).level == level


def test_verified_outweighs_pending_and_score_is_monotonic():
    assert score_reports(1, 0).score > score_reports(0, 3).score
    scores = [score_reports(v, 0).score for v in range(8)]
    assert scores == sorted(scores) and scores[-1] < 1.0


def test_level_boundaries():
    assert level_for(0.0) == RiskLevel.LOW
    assert level_for(0.2499) == RiskLevel.LOW
    assert level_for(0.25) == RiskLevel.MEDIUM
    assert level_for(0.5) == RiskLevel.HIGH
    assert level_for(0.75) == RiskLevel.CRITICAL
    assert level_for(1.0) == RiskLevel.CRITICAL


def test_confidence_capped_at_one():
    assert score_reports(50, 50).confidence == 1.0


def test_blocklist_overrides_low_automatic_score():
    r, override = combine(score_reports(0, 0), [RiskLevel.HIGH], allowlisted=False)
    assert override == "blocklist" and r.level == RiskLevel.HIGH and r.confidence == 1.0


def test_blocklist_never_lowers_a_higher_automatic_score():
    auto = score_reports(5, 0)  # critical
    r, _ = combine(auto, [RiskLevel.HIGH], allowlisted=False)
    assert r.level == RiskLevel.CRITICAL and r.score == auto.score


def test_blocklist_wins_over_allowlist():
    r, override = combine(score_reports(0, 0), [RiskLevel.CRITICAL], allowlisted=True)
    assert override == "blocklist" and r.level == RiskLevel.CRITICAL


def test_allowlist_zeroes_the_score():
    r, override = combine(score_reports(3, 4), [], allowlisted=True)
    assert override == "allowlist" and r.score == 0.0 and r.level == RiskLevel.LOW


def test_no_overrides_returns_automatic_result():
    auto = score_reports(1, 2)
    assert combine(auto, [], allowlisted=False) == (auto, None)


def test_assessment_combines_phone_message_and_transaction_evidence():
    assessment = assess_risk(
        PhoneReputation(verified_reporters=1),
        message=MessageIndicators(malicious_link_score=1.0, impersonation_score=0.8),
        transaction=TransactionContext(
            new_recipient=True, amount_anomaly_score=0.9, recipient_mismatch_score=0.8
        ),
    )

    assert assessment.override is None
    assert assessment.result.level == RiskLevel.CRITICAL
    assert assessment.components["phone_reputation"] == score_reports(1, 0).score
    assert assessment.components["message_indicators"] > 0
    assert assessment.components["transaction_context"] > 0
    assert "message contains a high-risk link" in assessment.reasons
    assert "transaction amount is unusual" in assessment.reasons


def test_assessment_ignores_invalid_signal_ranges_and_is_bounded():
    assessment = assess_risk(
        PhoneReputation(),
        message=MessageIndicators(
            suspicious_keyword_score=9, malicious_link_score=-1, indicator_count=-5
        ),
        transaction=TransactionContext(amount_anomaly_score=float("nan")),
    )

    assert 0 <= assessment.result.score <= 1
    assert assessment.result.level == RiskLevel.LOW


def test_assessment_manual_overrides_remain_authoritative():
    allowlisted = assess_risk(
        PhoneReputation(verified_reporters=3, allowlisted=True),
        message=MessageIndicators(malicious_link_score=1),
    )
    assert allowlisted.override == "allowlist"
    assert allowlisted.result.level == RiskLevel.LOW and allowlisted.result.score == 0

    blocklisted = assess_risk(
        PhoneReputation(blocklist_levels=(RiskLevel.HIGH,), allowlisted=True),
        transaction=TransactionContext(amount_anomaly_score=1),
    )
    assert blocklisted.override == "blocklist"
    assert blocklisted.result.level == RiskLevel.HIGH


def test_max_level():
    assert scoring.max_level([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.HIGH]) == RiskLevel.CRITICAL


@pytest.mark.parametrize("level", list(RiskLevel))
def test_short_message_fits_a_single_sms_and_is_ascii(level):
    for override in (None, "allowlist"):
        msg = short_message("+233241234567", level, known=True, verified=2, pending=3, override=override)
        assert len(msg) <= 160 and msg.isascii()


def test_short_message_wording():
    num = "+233241234567"
    assert "DANGER" in short_message(num, RiskLevel.HIGH, known=True, verified=2, pending=0, override=None)
    assert "CAUTION" in short_message(num, RiskLevel.MEDIUM, known=True, verified=1, pending=0, override=None)
    assert "no reports" in short_message(num, RiskLevel.LOW, known=False, verified=0, pending=0, override=None)
    assert "trusted" in short_message(num, RiskLevel.LOW, known=True, verified=0, pending=0, override="allowlist")
