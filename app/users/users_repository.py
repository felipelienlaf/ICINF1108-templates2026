from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.users.users_models import UserModel, UserSessionModel


class UsersRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def find_by_id(self, user_id: UUID) -> UserModel | None:
        return self.db.get(UserModel, user_id)

    def find_by_email(self, email: str) -> UserModel | None:
        return self.db.scalar(select(UserModel).where(UserModel.email == email))

    def add(self, user: UserModel) -> UserModel:
        self.db.add(user)
        self.db.flush()
        return user

    # Cierra todas las sesiones abiertas del usuario.
    def delete_sessions(self, user_id: UUID) -> None:
        self.db.execute(
            delete(UserSessionModel).where(UserSessionModel.userId == user_id)
        )