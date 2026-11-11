from sqlalchemy.orm import Session

from app.users.users_models import PasswordResetTokenModel


class ResetTokensRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def add(self, token: PasswordResetTokenModel) -> PasswordResetTokenModel:
        self.db.add(token)
        self.db.flush()
        return token