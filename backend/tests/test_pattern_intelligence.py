import pytest

from app.services.pattern_intelligence import (
    HeuristicPatternClassifier,
    analyze_patterns,
)
from app.services.shield import analyze_sms


def test_patterns_are_taxonomy_mapped_and_explainable():
    text = "URGENT! Bank support needs your OTP now."
    analysis = analyze_patterns(text, analyze_sms(text), classifier=HeuristicPatternClassifier())

    selected = {match.pattern_id for match in analysis.selected}
    assert {"FP002", "FP005"}.issubset(selected)
    assert analysis.model_version == "heuristic-patterns-1"
    assert analysis.hazard > 0
    assert all(match.counter_checks for match in analysis.selected)


def test_campaign_fingerprint_is_stable_for_same_signal_set():
    first = analyze_patterns("Please send your OTP to bank support", classifier=HeuristicPatternClassifier())
    second = analyze_patterns("Please send your OTP to bank support", classifier=HeuristicPatternClassifier())

    assert first.campaign_fingerprint == second.campaign_fingerprint
    assert len(first.campaign_fingerprint) == 24


def test_empty_pattern_input_is_rejected():
    with pytest.raises(ValueError):
        analyze_patterns("   ")
