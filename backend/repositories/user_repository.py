from sqlalchemy.orm import Session

from models.user import User


class UserRepository:

    def __init__(self, db: Session):
        self.db = db

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_by_username(self, username: str) -> User | None:
        return self.db.query(User).filter(
            User.username == username
        ).first()

    def get_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(
            User.email == email
        ).first()

    def get_by_id(self, user_id: int) -> User | None:
        return self.db.query(User).filter(
            User.id == user_id
        ).first()