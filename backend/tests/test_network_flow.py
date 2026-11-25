from tests.conftest import login


async def test_shield_pattern_links_are_visible_without_reporter_identity(client):
    headers = await login(client)
    number = "0247654321"
    analysis = await client.post(
        "/v1/shield/analyze", headers=headers,
        json={
            "phone_number": number,
            "text": "URGENT! Bank support needs your OTP now. https://bit.ly/verify",
        },
    )
    assert analysis.status_code == 200, analysis.text

    network = await client.post("/v1/network/number", headers=headers, json={"number": number})
    assert network.status_code == 200, network.text
    result = network.json()
    assert result["link_count"] >= 1
    assert result["related_patterns"]
    assert "reporter" not in network.text.lower()
