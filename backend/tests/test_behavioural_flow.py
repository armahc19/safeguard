from tests.conftest import login


async def test_transaction_assessment_uses_recent_history(client):
    headers = await login(client)
    first = await client.post(
        "/v1/transactions/assess", headers=headers,
        json={"recipient_number": "0241234567", "amount": 100, "currency": "GHS"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["behavior_signals"]["new_recipient"] is True

    second = await client.post(
        "/v1/transactions/assess", headers=headers,
        json={"recipient_number": "0241234567", "amount": 350, "currency": "GHS"},
    )
    assert second.status_code == 200, second.text
    signals = second.json()["behavior_signals"]
    assert signals["recipient_seen"] is True
    assert signals["amount_baseline"] == 100.0
    assert signals["amount_anomaly_score"] > 0
