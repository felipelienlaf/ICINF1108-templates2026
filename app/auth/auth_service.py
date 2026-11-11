from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.auth.auth_schemas import (
    ForgotPasswordDto,
    ForgotPasswordResponse,
    LoginDto,
    RegisterDto,
)
from app.auth.password import hash_password, verify_password
from app.auth.reset_token import create_reset_token
from app.auth.reset_tokens_repository import ResetTokensRepository
from app.shared.config import RESET_LINK_BASE_URL
from app.shared.database import DbSession
from app.shared.exceptions import conflict
from app.users.users_models import PasswordResetTokenModel, UserModel
from app.users.users_repository import UsersRepository

FORGOT_PASSWORD_MESSAGE = (
    "Si el correo está registrado, se generó un enlace para recuperar la contraseña"
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

    # Pasos 2 a 8 del diagrama de "recuperar contraseña". Siempre responde 200
    # con el mismo mensaje, exista o no el correo. En un sistema real el enlace
    # se enviaría por correo y la respuesta no lo incluiría.
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


AuthServiceDep = Annotated[AuthService, Depends()]