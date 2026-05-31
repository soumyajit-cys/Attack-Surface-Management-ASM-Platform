from datetime import datetime, timedelta

from jose import jwt

SECRET = "CHANGE_ME"

ALGORITHM = "HS256"


def create_access_token(data: dict):

    payload = data.copy()

    payload["exp"] = (
        datetime.utcnow() + timedelta(minutes=30)
    )

    return jwt.encode(
        payload,
        SECRET,
        algorithm=ALGORITHM
    )



