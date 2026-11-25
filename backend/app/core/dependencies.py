import jwt
from fastapi import Cookie, HTTPException

from app.core.db import AsyncSessionLocal
from app.core.models import User
from app.core.security import decode_access_token


async def get_current_user(
    access_token: str | None = Cookie(default=None),
) -> User:
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        user_id = decode_access_token(access_token)
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid or expired session"
        ) from exc

    async with AsyncSessionLocal() as db:
        user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
