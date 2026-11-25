import asyncio
from types import SimpleNamespace

import pytest

from app.api.routes.gateway import _voice_momo_amount, _voice_momo_intent
from app.services.momo_sandbox import MomoSandbox


def test_voice_momo_intents_and_amount_followups():
    history = [SimpleNamespace(role="user", text="I want to send money")]
    assert _voice_momo_intent("yes, confirm", history) == "send"
    assert _voice_momo_intent("check my balance", []) == "balance"
    assert _voice_momo_intent("show money I received", []) == "received"
    assert _voice_momo_amount(["Send GH₵50 to +233241234567"]) == "50"
    assert _voice_momo_amount(["50 cedis"]) == "50"


def test_momo_sandbox_balances_received_and_confirmed_transfer():
    async def scenario():
        sandbox = MomoSandbox()
        sender, recipient = "+233241111111", "+233242222222"
        initial = await sandbox.balance(sender)
        assert initial == {"number": sender, "balance": "1000.00", "currency": "GHS", "simulated": True}
        assert (await sandbox.received(sender))["items"]

        staged = await sandbox.stage_transfer(sender, recipient, "50")
        assert staged["amount"] == "50.00"
        assert (await sandbox.balance(sender))["balance"] == "1000.00"
        transfer = await sandbox.confirm_transfer(sender)
        assert transfer["status"] == "completed" and transfer["simulated"] is True
        assert (await sandbox.balance(sender))["balance"] == "950.00"
        received = await sandbox.received(recipient)
        assert received["items"][0]["amount"] == "50.00"
        with pytest.raises(ValueError, match="no pending"):
            await sandbox.confirm_transfer(sender)
        await sandbox.reset()

    asyncio.run(scenario())


def test_momo_sandbox_rejects_invalid_or_unsafe_transfers():
    async def scenario():
        sandbox = MomoSandbox()
        with pytest.raises(ValueError, match="greater than"):
            await sandbox.stage_transfer("+233241111111", "+233242222222", "0")
        with pytest.raises(ValueError, match="different from your own"):
            await sandbox.stage_transfer("+233241111111", "+233241111111", "10")
        with pytest.raises(ValueError, match="not have enough"):
            await sandbox.stage_transfer("+233241111111", "+233242222222", "1001")

    asyncio.run(scenario())
