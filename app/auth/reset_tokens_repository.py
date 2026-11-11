from datetime import datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.users.users_models import PasswordResetTokenModel


class ResetTokensRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def add(self, token: PasswordResetTokenModel) -> PasswordResetTokenModel:
        self.db.add(token)
        self.db.flush()
        return token

    def find_by_jti(self, jti: str) -> PasswordResetTokenModel | None:
        return self.db.get(PasswordResetTokenModel, jti)

    # Marca el token como usado solo si seguía pendiente. Al ser un UPDATE
    # condicional, si llegan dos peticiones a la vez solo una lo consigue:
    # eso es lo que garantiza que el enlace sea de un solo uso.
    def mark_used(self, jti: str, used_at: datetime) -> bool:
        result = self.db.execute(
            update(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.jti == jti,
                PasswordResetTokenModel.usedAt.is_(None),
            )
            .values({PasswordResetTokenModel.usedAt: used_at})
        )
        return result.rowcount == 1