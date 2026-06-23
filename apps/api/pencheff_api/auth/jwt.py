from datetime import datetime, timedelta, timezone

import jwt

from ..config import get_settings

_settings = get_settings()


def _encode(payload: dict, ttl: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {**payload, "iat": int(now.timestamp()), "exp": int((now + ttl).timestamp())}
    return jwt.encode(payload, _settings.jwt_secret, algorithm=_settings.jwt_algorithm)


def make_access_token(user_id: str, org_id: str) -> str:
    return _encode({"sub": user_id, "org": org_id, "type": "access"}, timedelta(minutes=_settings.access_token_ttl_minutes))


def make_refresh_token(user_id: str, org_id: str) -> str:
    return _encode({"sub": user_id, "org": org_id, "type": "refresh"}, timedelta(days=_settings.refresh_token_ttl_days))


def decode_token(token: str) -> dict:
    return jwt.decode(token, _settings.jwt_secret, algorithms=[_settings.jwt_algorithm])
