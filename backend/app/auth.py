from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from .config import PREDEFINED_USERS, settings


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Simple authentication for predefined users (prototype / research-grade).
    No bcrypt here to avoid Windows/Rust issues.
    """
    user = PREDEFINED_USERS.get(username)
    if not user:
        return None

    if password != user["password_plain"]:
        return None

    return user


def create_access_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.jwt_exp_minutes)

    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": exp,
    }

    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        sub = payload.get("sub")
        return sub if isinstance(sub, str) else None
    except JWTError:
        return None
