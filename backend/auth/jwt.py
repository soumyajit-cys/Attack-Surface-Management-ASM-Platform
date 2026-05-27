from jose import jwt

SECRET="secret"

ALGORITHM="HS256"


def create_token(data):

    return jwt.encode(
        data,
        SECRET,
        algorithm=ALGORITHM
    )