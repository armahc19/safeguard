"""In-memory simulated MoMo service. It never contacts a payment provider."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from uuid import uuid4


class MomoSandbox:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._balances: dict[str, Decimal] = {}
        self._transactions: list[dict] = []
        self._pending: dict[str, tuple[str, Decimal]] = {}

    def _ensure_wallet(self, number: str) -> None:
        if number not in self._balances:
            self._balances[number] = Decimal("1000.00")
            self._transactions.append({
                "id": f"SIM-RCV-{uuid4().hex[:10].upper()}", "type": "received",
                "sender": "+233200000099", "recipient": number, "amount": "25.00",
                "currency": "GHS", "status": "completed", "simulated": True,
                "created_at": datetime.now(UTC).isoformat(),
            })

    async def balance(self, number: str) -> dict:
        async with self._lock:
            self._ensure_wallet(number)
            return {"number": number, "balance": str(self._balances[number]), "currency": "GHS",
                    "simulated": True}

    async def received(self, number: str, limit: int = 5) -> dict:
        async with self._lock:
            self._ensure_wallet(number)
            rows = [row.copy() for row in reversed(self._transactions)
                    if row["recipient"] == number and row["type"] == "received"][:limit]
            return {"items": rows, "simulated": True}

    async def stage_transfer(self, sender: str, recipient: str, amount: str | Decimal) -> dict:
        try:
            value = Decimal(str(amount)).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError):
            raise ValueError("Enter a valid amount in Ghana cedis.") from None
        if value <= 0 or value > Decimal("5000.00"):
            raise ValueError("Sandbox transfers must be greater than GH₵0 and no more than GH₵5,000.")
        if recipient == sender:
            raise ValueError("Choose a recipient number different from your own.")
        async with self._lock:
            self._ensure_wallet(sender)
            self._ensure_wallet(recipient)
            if value > self._balances[sender]:
                raise ValueError("The simulated wallet does not have enough balance.")
            self._pending[sender] = (recipient, value)
        return {"recipient": recipient, "amount": str(value), "currency": "GHS", "simulated": True}

    async def confirm_transfer(self, sender: str) -> dict:
        async with self._lock:
            pending = self._pending.pop(sender, None)
            if pending is None:
                raise ValueError("There is no pending simulated transfer to confirm.")
            recipient, amount = pending
            self._ensure_wallet(sender)
            self._ensure_wallet(recipient)
            if amount > self._balances[sender]:
                raise ValueError("The simulated wallet no longer has enough balance.")
            self._balances[sender] -= amount
            self._balances[recipient] += amount
            now = datetime.now(UTC).isoformat()
            reference = f"SIM-{uuid4().hex[:12].upper()}"
            self._transactions.extend([
                {"id": reference, "type": "sent", "sender": sender, "recipient": recipient,
                 "amount": str(amount), "currency": "GHS", "status": "completed",
                 "simulated": True, "created_at": now},
                {"id": reference, "type": "received", "sender": sender, "recipient": recipient,
                 "amount": str(amount), "currency": "GHS", "status": "completed",
                 "simulated": True, "created_at": now},
            ])
            return {"reference": reference, "sender": sender, "recipient": recipient,
                    "amount": str(amount), "currency": "GHS", "status": "completed",
                    "simulated": True}

    async def cancel_transfer(self, sender: str) -> None:
        async with self._lock:
            self._pending.pop(sender, None)

    async def reset(self) -> None:
        async with self._lock:
            self._balances.clear()
            self._transactions.clear()
            self._pending.clear()


momo_sandbox = MomoSandbox()
