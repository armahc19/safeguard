from app.schemas.conversation import SharedCaseContext
from app.services.conversation_intelligence import _retrieve_cases


def test_conversation_retrieval_returns_explainable_candidates():
    matches = _retrieve_cases("mistakenly sent money please send it back", limit=3)

    assert len(matches) <= 3
    if matches:
        assert matches[0].case_id
        assert matches[0].retrieval_score > 0
        assert matches[0].summary


def test_shared_case_context_has_no_raw_message_field():
    context = SharedCaseContext(case_id="00000000-0000-0000-0000-000000000001")

    assert context.turn_count == 0
    assert not hasattr(context, "messages")
    assert not hasattr(context, "raw_text")
