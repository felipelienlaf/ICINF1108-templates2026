from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.auth.auth_schemas import (
    ForgotPasswordDto,
    ForgotPasswordResponse,
    LoginDto,
    RegisterDto,
    ResetPasswordDto,
    ResetPasswordResponse,
)
from app.auth.password import hash_password, verify_password
from app.auth.reset_token import (
    InvalidResetToken,
    create_reset_token,
    decode_reset_token,
)
from app.auth.reset_tokens_repository import ResetTokensRepository
from app.shared.config import RESET_LINK_BASE_URL
from app.shared.database import DbSession, parse_uuid
from app.shared.datetimes import utc_now
from app.shared.exceptions import conflict
from app.users.users_models import PasswordResetTokenModel, UserModel
from app.users.users_repository import UsersRepository

FORGOT_PASSWORD_MESSAGE = (
    "Si el correo está registrado, se generó un enlace para recuperar la contraseña"
)
RESET_PASSWORD_MESSAGE = "La contraseña se actualizó correctamente"
RESET_LINK_INVALID_MESSAGE = "El enlace de recuperación no es válido o ya expiró"


# Mismo error para token mal formado, expirado, ya usado o inexistente, para no
# dar pistas sobre cuál de los casos fue.
def _invalid_reset_link() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=RESET_LINK_INVALID_MESSAGE
    )


class AuthService:
    def __init__(self, db: DbSession) -> None:
        self.db = db
        self.users_repository = UsersRepository(db)
        self.reset_tokens_repository = ResetTokensRepository(db)

    def register(self, data: RegisterDto) -> UserModel:
        if self.users_repository.find_by_email(data.email) is not None:
            raise conflict(
                {"email": {"message": "El correo electrónico ya está registrado"}}
            )

        user = self.users_repository.add(
            UserModel(
                name=data.name,
                email=data.email,
                passwordHash=hash_password(data.password),
            )
        )
        self.db.commit()

        return user

    def login(self, data: LoginDto) -> UserModel:
        user = self.users_repository.find_by_email(data.email)

        # Mismo mensaje si el correo no existe o la contraseña es incorrecta,
        # para no revelar qué correos están registrados.
        if user is None or not verify_password(data.password, user.passwordHash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Correo o contraseña incorrectos",
            )

        return user

    # Diagrama de "recuperar contraseña": busca al usuario, genera el JWT y
    # guarda el jti pendiente. Siempre responde 200 con el mismo mensaje, exista
    # o no el correo. En un sistema real el enlace se enviaría por correo y la
    # respuesta no lo incluiría.
    def forgot_password(self, data: ForgotPasswordDto) -> ForgotPasswordResponse:
        user = self.users_repository.find_by_email(data.email)
        reset_link: str | None = None

        if user is not None:
            token, jti, expires_at = create_reset_token(user.id)
            self.reset_tokens_repository.add(
                PasswordResetTokenModel(
                    jti=jti, userId=user.id, expiresAt=expires_at
                )
            )
            self.db.commit()
            reset_link = f"{RESET_LINK_BASE_URL}?token={token}"

        return ForgotPasswordResponse(
            message=FORGOT_PASSWORD_MESSAGE, reset_link=reset_link
        )

    # 1) valida el JWT, 2) comprueba que el jti siga pendiente, 3) cambia la
    # contraseña y 4) marca el token como usado. Todo se confirma junto.
    def reset_password(self, data: ResetPasswordDto) -> ResetPasswordResponse:
        try:
            payload = decode_reset_token(data.token)
        except InvalidResetToken:
            raise _invalid_reset_link() from None

        user_id = parse_uuid(payload["sub"])
        record = self.reset_tokens_repository.find_by_jti(payload["jti"])

        if (
            user_id is None
            or record is None
            or record.userId != user_id
            or record.usedAt is not None
        ):
            raise _invalid_reset_link()

        user = self.users_repository.find_by_id(user_id)
        if user is None:
            raise _invalid_reset_link()

        # Si otra petición ya lo usó en el mismo instante, esto devuelve False.
        if not self.reset_tokens_repository.mark_used(record.jti, utc_now()):
            raise _invalid_reset_link()

        user.passwordHash = hash_password(data.password)
        # Por seguridad se cierran las sesiones que el usuario tuviera abiertas.
        self.users_repository.delete_sessions(user.id)
        self.db.commit()

        return ResetPasswordResponse(message=RESET_PASSWORD_MESSAGE)


AuthServiceDep = Annotated[AuthService, Depends()]