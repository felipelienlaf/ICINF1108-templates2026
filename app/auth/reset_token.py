import uuid
from datetime import datetime, timedelta
from uuid import UUID

import jwt

from app.shared.config import RESET_TOKEN_EXPIRE_MINUTES, RESET_TOKEN_SECRET
from app.shared.datetimes import utc_now

ALGORITHM = "HS256"
PURPOSE = "password_reset"


class InvalidResetToken(Exception):
    """El token es inválido, expiró o no es de recuperación de contraseña."""


def _secret() -> str:
    if not RESET_TOKEN_SECRET:
        raise RuntimeError("Falta la variable de entorno RESET_TOKEN_SECRET")
    return RESET_TOKEN_SECRET


# Devuelve (token, jti, expires_at). El jti se guarda como pendiente en la DB:
# eso es lo que hace que el enlace sea de un solo uso.
def create_reset_token(user_id: UUID) -> tuple[str, str, datetime]:
    now = utc_now()
    expires_at = now + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    jti = uuid.uuid4().hex

    payload = {
        "sub": str(user_id),
        "jti": jti,
        "purpose": PURPOSE,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, _secret(), algorithm=ALGORITHM)

    return token, jti, expires_at


# Valida firma, expiración y propósito. Que el jti siga pendiente se comprueba
# contra la base de datos en el paso de reset.
def decode_reset_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidResetToken from exc

    if payload.get("purpose") != PURPOSE:
        raise InvalidResetToken

    return payload