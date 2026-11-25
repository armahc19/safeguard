"""Create local demo FIR/PDR data and an admin login for the web console.

Run from ``backend`` after applying migrations:
    python scripts/seed_intelligence_demo.py
"""
import asyncio
import os
import sys
from pathlib import Path

# Support the documented direct invocation: ``python scripts/seed_intelligence_demo.py``.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import select

from app.core.config import get_settings
from app.core.exceptions import PermissionDenied
from app.core.phone import normalize_phone
from app.db.session import create_engine, create_session_factory
from app.enums import UserRole
from app.models import User
from app.services.admin_intelligence import seed_intelligence_demo


async def main() -> None:
    settings = get_settings()
    if settings.environment not in {"development", "test"}:
        raise PermissionDenied("Demo seeding is restricted to development or test environments.")
    phone = normalize_phone(os.getenv("SAFEGUARD_DEMO_ADMIN_PHONE", "+233200000001"),
                            settings.default_calling_code)
    engine = create_engine(settings)
    sessions = create_session_factory(engine)
    try:
        async with sessions() as db:
            admin = await db.scalar(select(User).where(User.phone == phone))
            if admin is None:
                admin = User(phone=phone, role=UserRole.ADMIN)
                db.add(admin)
                await db.commit()
                await db.refresh(admin)
            elif admin.role != UserRole.ADMIN:
                admin.role = UserRole.ADMIN
                await db.commit()
            result = await seed_intelligence_demo(db, admin, settings)
            print(f"Demo admin phone: {phone}")
            print(f"Seed result: {result}")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
