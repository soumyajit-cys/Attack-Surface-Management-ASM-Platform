from sqlalchemy.orm import Session

from models.user import User


class UserRepository:

    def __init__(self, db: Session):

        self.db = db

    def create(self, user):

        self.db.add(user)

        self.db.commit()

        self.db.refresh(user)

        return user

    def get_by_username(self, username):

        return self.db.query(User).filter(
            User.username == username
        ).first()
    

    