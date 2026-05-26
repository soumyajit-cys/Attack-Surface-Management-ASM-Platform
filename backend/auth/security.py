from passlib.context import CryptContext

pwd=CryptContext(
    schemes=["bcrypt"]
)

def hash_password(v):

    return pwd.hash(v)


def verify(v,h):

    return pwd.verify(v,h)

