import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.enums import AccountStatus, UserRole


class OTPRequest(BaseModel):
    phone: str = Field(min_length=7, max_length=20)


class OTPVerify(BaseModel):
    phone: str = Field(min_length=7, max_length=20)
    code: str = Field(pattern=r"^\d{4,8}$")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access token lifetime, seconds


class MessageOut(BaseModel):
    message: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    phone: str
    role: UserRole
    account_status: AccountStatus
    created_at: datetime
