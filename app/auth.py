from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from .models import User
from .policy import require_access
from .seed import passwords

router = APIRouter()
# Same-cost verification for unknown usernames; no plaintext passwords retained.
DUMMY_HASH = passwords.hash("unusable-placeholder")


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=60)
    password: str = Field(min_length=1, max_length=128)


def public_user(user):
    return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role}


def issue_token(user, secret):
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user.username, "role": user.role, "iat": now,
                       "exp": now + timedelta(minutes=15), "ver": user.token_version}, secret, algorithm="HS256")


@router.post("/auth/login")
async def login(body: Credentials, request: Request):
    # Serialize with reset so a successful login never reads a partially reseeded DB.
    async with request.app.state.gateway_lock:
        with request.app.state.db.Session() as session:
            user = session.scalar(select(User).where(User.username == body.username))
            valid = passwords.verify(body.password, user.password_hash if user else DUMMY_HASH)
            if not user or not valid:
                raise HTTPException(401, "Неверное имя пользователя или пароль")
            return {"access_token": issue_token(user, request.app.state.settings.jwt_secret),
                    "token_type": "bearer", "expires_in": 900, "user": public_user(user)}


@router.get("/api/me")
async def me(request: Request):
    return require_access(getattr(request.state, "user", None), "me.read")
