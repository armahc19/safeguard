from tests.conftest import login


async def test_call_analysis_returns_privacy_safe_result(client):
    headers = await login(client)
    response = await client.post(
        "/v1/calls/analyze", headers=headers,
        json={
            "caller_number": "0241234567",
            "user_activated_protection": True,
            "consented_transcript": True,
            "transcript": "URGENT! Bank support needs your OTP now.",
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["transcript_recorded"] is False
    assert result["transcript_hash"]
    assert "does not record call audio" in result["privacy_notice"]

    case = await client.get(f"/v1/cases/{result['case_id']}", headers=headers)
    assert case.status_code == 200
    assert "URGENT! Bank support needs your OTP now." not in case.text
