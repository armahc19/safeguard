from tests.conftest import login


async def test_case_lifecycle_and_evidence_ownership(client):
    headers = await login(client)
    created = await client.post(
        "/v1/cases", headers=headers,
        json={"title": "Suspicious caller", "summary": "Caller requested an OTP"},
    )
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]

    evidence = await client.post(
        f"/v1/cases/{case_id}/evidence", headers=headers,
        json={
            "evidence_type": "phone_number",
            "source": "user_report",
            "value": "+233241234567",
            "confidence": 0.8,
            "details": {"requested_secret": True},
        },
    )
    assert evidence.status_code == 201, evidence.text

    detail = await client.get(f"/v1/cases/{case_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["evidence_count"] == 1
    assert detail.json()["evidence"][0]["details"]["requested_secret"] is True

    closed = await client.post(f"/v1/cases/{case_id}/close", headers=headers)
    assert closed.status_code == 200 and closed.json()["status"] == "closed"

    rejected = await client.post(
        f"/v1/cases/{case_id}/evidence", headers=headers,
        json={"evidence_type": "other", "source": "test"},
    )
    assert rejected.status_code == 422 and rejected.json()["error"]["code"] == "case_closed"
