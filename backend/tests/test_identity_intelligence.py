from app.services.identity_intelligence import assess_identity


def test_identity_analysis_detects_credential_harvesting_impersonation():
    result = assess_identity("I am from bank support. Send your OTP now at http://bit.ly/verify")

    assert result.claimed_identity == "Bank or financial institution"
    assert result.label == "possible_impersonation"
    assert result.identity_score >= 0.55
    assert result.contradictions
    assert "identity_registry" in result.provenance


def test_identity_analysis_records_official_domain_without_treating_it_as_proof():
    result = assess_identity("Visit https://mtn.com.gh for help")

    assert result.official_domain_match is True
    assert result.label in {"official_reference_present", "no_identity_claim"}
    assert result.identity_score <= 0.1


def test_identity_analysis_is_uncertain_without_a_claim():
    result = assess_identity("Your meeting is tomorrow at 10am.")

    assert result.label == "no_identity_claim"
    assert result.claimed_identity is None
    assert result.identity_score == 0.0
    assert result.unknowns
