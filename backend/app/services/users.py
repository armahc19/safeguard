from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User


async def get_or_create_user(db: AsyncSession, phone: str) -> User:
    """`phone` must already be normalised to E.164."""
    user = await db.scalar(select(User).where(User.phone == phone))
    if user:
        return user
    user = User(phone=phone)
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:  # concurrent first login / first gateway request for the same number
        await db.rollback()
        user = await db.scalar(select(User).where(User.phone == phone))
        assert user is not None
    return user
