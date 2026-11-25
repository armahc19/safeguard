"""End-to-end Fraud Intelligence flow (needs TEST_DATABASE_URL; see conftest.py)."""
import hashlib
import hmac
import json
import time

from tests.conftest import login

SCAM = "0551112222"  # +233551112222


async def report(client, headers, number=SCAM, **kw):
    return await client.post("/v1/reports", headers=headers,
                             json={"number": number, "report_type": "call", **kw})


async def lookup(client, headers, number=SCAM):
    r = await client.post("/v1/numbers/lookup", headers=headers, json={"number": number})
    assert r.status_code == 200, r.text
    return r.json()


async def test_unknown_number_is_low_and_not_known(client):
    h = await login(client)
    out = await lookup(client, h)
    assert out["known"] is False and out["risk_level"] == "low" and out["verified_reports"] == 0


async def test_report_review_lookup_lifecycle(client):
    alice, bob = await login(client, "0241111111"), await login(client, "0242222222")
    reviewer = await login(client, "0243333333", role="reviewer")
    admin = await login(client, "0244444444", role="admin")

    cat = await client.post("/v1/scam-categories", headers=admin, json={"name": "Fake mobile money"})
    assert cat.status_code == 201
    category_id = cat.json()["id"]

    r1 = await report(client, alice, description="Asked for my PIN")
    assert r1.status_code == 201 and r1.json()["status"] == "pending" and r1.json()["phone"] == "+233551112222"
    assert (await report(client, alice)).status_code == 409  # duplicate within 24h

    after_pending = await lookup(client, bob)
    assert after_pending["known"] and after_pending["pending_reports"] == 1 and after_pending["risk_level"] == "low"

    # a plain user can't see the queue or review
    assert (await client.get("/v1/reports", headers=alice)).status_code == 403
    assert (await client.post(f"/v1/reports/{r1.json()['id']}/review", headers=alice,
                              json={"decision": "approved"})).status_code == 403

    queue = await client.get("/v1/reports", headers=reviewer)
    assert queue.json()["total"] == 1

    reviewed = await client.post(f"/v1/reports/{r1.json()['id']}/review", headers=reviewer,
                                 json={"decision": "approved", "category_id": category_id})
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "verified"
    assert (await client.post(f"/v1/reports/{r1.json()['id']}/review", headers=reviewer,
                              json={"decision": "rejected"})).json()["error"]["code"] == "already_reviewed"

    after_verified = await lookup(client, bob)
    assert after_verified["verified_reports"] == 1 and after_verified["risk_level"] == "medium"
    assert after_verified["categories"] == ["Fake mobile money"]

    # a second distinct reporter, verified, lifts the number to high
    r2 = await report(client, bob)
    await client.post(f"/v1/reports/{r2.json()['id']}/review", headers=reviewer, json={"decision": "approved"})
    assert (await lookup(client, alice))["risk_level"] == "high"

    mine = await client.get("/v1/reports/mine", headers=alice)
    assert mine.json()["total"] == 1
    # others' reports are invisible (404, not 403)
    assert (await client.get(f"/v1/reports/{r2.json()['id']}", headers=alice)).status_code == 404


async def test_rejected_report_adds_no_risk(client):
    alice = await login(client, "0241111111")
    reviewer = await login(client, "0243333333", role="reviewer")
    r = await report(client, alice)
    await client.post(f"/v1/reports/{r.json()['id']}/review", headers=reviewer, json={"decision": "rejected"})
    out = await lookup(client, alice)
    assert out["pending_reports"] == 0 and out["verified_reports"] == 0 and out["risk_level"] == "low"


async def test_needs_info_can_be_followed_by_final_decision(client):
    alice = await login(client, "0241111111")
    reviewer = await login(client, "0243333333", role="reviewer")
    r = await report(client, alice)
    rid = r.json()["id"]
    first = await client.post(f"/v1/reports/{rid}/review", headers=reviewer, json={"decision": "needs_info"})
    assert first.json()["status"] == "under_review"
    second = await client.post(f"/v1/reports/{rid}/review", headers=reviewer, json={"decision": "approved"})
    assert second.json()["status"] == "verified"


async def test_reporting_rules(client):
    alice = await login(client, "0241111111")
    assert (await report(client, alice, number="0241111111")).json()["error"]["code"] == "own_number"
    reviewer = await login(client, "0243333333", role="reviewer")
    r = await report(client, reviewer)  # reviewers can report too, but never review their own report
    res = await client.post(f"/v1/reports/{r.json()['id']}/review", headers=reviewer, json={"decision": "approved"})
    assert res.json()["error"]["code"] == "own_report"


async def test_blocklist_allowlist_and_permissions(client):
    reviewer = await login(client, "0243333333", role="reviewer")
    admin = await login(client, "0244444444", role="admin")
    user = await login(client, "0241111111")

    assert (await client.post("/v1/threats", headers=user, json={"number": SCAM, "indicator_type": "blocklist"})).status_code == 403

    b = await client.post("/v1/threats", headers=reviewer, json={"number": SCAM, "indicator_type": "blocklist",
                                                                 "risk_level": "critical"})
    assert b.status_code == 201
    assert (await lookup(client, user))["risk_level"] == "critical"
    dup = await client.post("/v1/threats", headers=reviewer, json={"number": SCAM, "indicator_type": "blocklist"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "threat_exists"
    low = await client.post("/v1/threats", headers=reviewer, json={"number": "0556667777", "indicator_type": "blocklist",
                                                                   "risk_level": "low"})
    assert low.status_code == 422

    # allowlist is admin-only
    a_body = {"number": "0302000000", "indicator_type": "allowlist"}
    assert (await client.post("/v1/threats", headers=reviewer, json=a_body)).status_code == 403
    a = await client.post("/v1/threats", headers=admin, json=a_body)
    assert a.status_code == 201
    allowed = await lookup(client, user, "0302000000")
    assert allowed["override"] == "allowlist" and allowed["risk_level"] == "low"
    assert (await client.delete(f"/v1/threats/{a.json()['id']}", headers=reviewer)).status_code == 403

    # edit and remove a blocklist entry
    upd = await client.patch(f"/v1/threats/{b.json()['id']}", headers=reviewer, json={"risk_level": "high"})
    assert upd.json()["risk_level"] == "high"
    assert (await client.delete(f"/v1/threats/{b.json()['id']}", headers=reviewer)).status_code == 204
    assert (await lookup(client, user))["override"] is None

    # automatic indicators can't be edited
    listing = await client.get("/v1/threats", headers=reviewer, params={"indicator_type": "allowlist"})
    assert listing.json()["total"] == 1


async def test_automatic_indicators_are_not_editable(client):
    alice = await login(client, "0241111111")
    reviewer = await login(client, "0243333333", role="reviewer")
    await report(client, alice)
    auto = (await client.get("/v1/threats", headers=reviewer, params={"indicator_type": "report_volume"})).json()
    assert auto["total"] == 1
    r = await client.patch(f"/v1/threats/{auto['items'][0]['id']}", headers=reviewer, json={"confidence": 0.1})
    assert r.status_code == 409 and r.json()["error"]["code"] == "indicator_not_editable"


def _signed(body: dict, secret="ussd-secret", gateway="ussd", ts=None):
    raw = json.dumps(body).encode()
    ts = ts or str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return {"content": raw, "headers": {"X-Gateway-Id": gateway, "X-Timestamp": ts, "X-Signature": sig,
                                        "Content-Type": "application/json"}}


async def test_gateway_lookup_and_report(client):
    ok = await client.post("/v1/gateway/reports", **_signed({"msisdn": "0200000001", "number": SCAM}))
    assert ok.status_code == 201 and "report_id" in ok.json()

    look = await client.post("/v1/gateway/lookup", **_signed({"msisdn": "0200000002", "number": SCAM}))
    assert look.status_code == 200 and len(look.json()["short_message"]) <= 160 and look.json()["pending_reports"] == 1

    bad_sig = _signed({"msisdn": "0200000002", "number": SCAM}, secret="wrong")
    assert (await client.post("/v1/gateway/lookup", **bad_sig)).status_code == 401
    stale = _signed({"msisdn": "0200000002", "number": SCAM}, ts=str(int(time.time()) - 3600))
    assert (await client.post("/v1/gateway/lookup", **stale)).status_code == 401
    assert (await client.post("/v1/gateway/lookup", json={"msisdn": "0200000002", "number": SCAM})).status_code == 401
