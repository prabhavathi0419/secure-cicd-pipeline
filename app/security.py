"""Password hashing and token handling."""
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import Settings

# Argon2id: memory-hard, the OWASP-recommended password hash. Salt is automatic.
_hasher = PasswordHasher()
# Used to burn equal time when a username doesn't exist (blunts user enumeration by timing).
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        matched = _hasher.verify(stored_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return matched and stored_hash is not None


def create_token(username: str, settings: Settings) -> str:
    now = int(time.time())
    claims = {
        "sub": username,
        "iss": settings.token_issuer,
        "iat": now,
        "exp": now + settings.token_ttl_minutes * 60,
    }
    return jwt.encode(claims, settings.secret_key, algorithm="HS256")


def decode_token(token: str, settings: Settings) -> str | None:
    """Return the username, or None if invalid/expired. Algorithm is pinned (no 'alg: none')."""
    try:
        claims = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=settings.token_issuer,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.PyJWTError:
        return None
    return claims.get("sub")
