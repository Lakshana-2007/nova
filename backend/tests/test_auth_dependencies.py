from unittest.mock import Mock

import jwt
import pytest
from fastapi import HTTPException

from app.core import dependencies


class FakeSession:
    def __init__(self, user):
        self.user = user
        self.requested_user = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, model, user_id):
        self.requested_user = (model, user_id)
        return self.user


@pytest.mark.asyncio
async def test_missing_access_token_returns_401(monkeypatch):
    decode = Mock()
    session_factory = Mock()
    monkeypatch.setattr(dependencies, "decode_access_token", decode)
    monkeypatch.setattr(dependencies, "AsyncSessionLocal", session_factory)

    with pytest.raises(HTTPException) as exc_info:
        await dependencies.get_current_user(access_token=None)

    assert exc_info.value.status_code == 401
    decode.assert_not_called()
    session_factory.assert_not_called()


@pytest.mark.parametrize(
    "decode_error",
    [
        jwt.InvalidTokenError("invalid token"),
        jwt.ExpiredSignatureError("expired token"),
        ValueError("malformed subject"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_or_malformed_access_token_returns_401(
    monkeypatch, decode_error
):
    decode = Mock(side_effect=decode_error)
    session_factory = Mock()
    monkeypatch.setattr(dependencies, "decode_access_token", decode)
    monkeypatch.setattr(dependencies, "AsyncSessionLocal", session_factory)

    with pytest.raises(HTTPException) as exc_info:
        await dependencies.get_current_user(access_token="bad-token")

    assert exc_info.value.status_code == 401
    decode.assert_called_once_with("bad-token")
    session_factory.assert_not_called()


@pytest.mark.asyncio
async def test_valid_access_token_returns_existing_user(monkeypatch):
    user = object()
    session = FakeSession(user)
    decode = Mock(return_value=42)
    monkeypatch.setattr(dependencies, "decode_access_token", decode)
    monkeypatch.setattr(
        dependencies, "AsyncSessionLocal", Mock(return_value=session)
    )

    result = await dependencies.get_current_user(access_token="valid-token")

    assert result is user
    assert session.requested_user == (dependencies.User, 42)
    decode.assert_called_once_with("valid-token")


@pytest.mark.asyncio
async def test_valid_access_token_for_missing_user_returns_401(monkeypatch):
    session = FakeSession(None)
    monkeypatch.setattr(
        dependencies, "decode_access_token", Mock(return_value=42)
    )
    monkeypatch.setattr(
        dependencies, "AsyncSessionLocal", Mock(return_value=session)
    )

    with pytest.raises(HTTPException) as exc_info:
        await dependencies.get_current_user(access_token="valid-token")

    assert exc_info.value.status_code == 401
    assert session.requested_user == (dependencies.User, 42)
