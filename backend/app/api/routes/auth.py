from fastapi import APIRouter, Request, status

from app.api.deps import AuthServiceDep, CurrentUser
from app.schemas.auth import (
    MessageOut,
    OTPRequest,
    OTPVerify,
    RefreshRequest,
    TokenPair,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/otp/request", response_model=MessageOut, status_code=status.HTTP_202_ACCEPTED)
async def request_otp(body: OTPRequest, request: Request, auth: AuthServiceDep) -> MessageOut:
    client_ip = request.client.host if request.client else None
    await auth.request_otp(body.phone, client_ip)
    # Same response whether or not the number already has an account.
    return MessageOut(message="If the number is valid, a verification code has been sent.")


@router.post("/otp/verify", response_model=TokenPair)
async def verify_otp(body: OTPVerify, auth: AuthServiceDep) -> TokenPair:
    return await auth.verify_otp(body.phone, body.code)


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, auth: AuthServiceDep) -> TokenPair:
    return await auth.refresh(body.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, auth: AuthServiceDep) -> None:
    await auth.logout(body.refresh_token)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
