from tests.conftest import login


async def test_case_feedback_records_outcome_and_rating(client):
    headers = await login(client)
    created = await client.post("/v1/cases", headers=headers, json={"title": "Feedback case"})
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]

    feedback = await client.post(
        f"/v1/cases/{case_id}/feedback", headers=headers,
        json={
            "outcome": "loss_prevented",
            "intervention_action": "stop_and_escalate",
            "followed_recommendation": True,
            "fraud_confirmed": True,
            "rating": 5,
            "notes": "  Stopped before sending money.  ",
        },
    )
    assert feedback.status_code == 201, feedback.text
    assert feedback.json()["notes"] == "Stopped before sending money."

    listed = await client.get(f"/v1/cases/{case_id}/feedback", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["outcome"] == "loss_prevented"
