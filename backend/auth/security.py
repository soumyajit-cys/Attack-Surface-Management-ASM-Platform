import bcrypt


# Timing-shape filler for unknown-user logins: verifying any password against
# this constant costs one bcrypt, matching a real password check. The
# preimage ("lockout-dummy-filler") is not a secret and grants nothing; it
# exists only so unknown-user and wrong-password attempts take the same path.
DUMMY_PASSWORD_PREIMAGE = "lockout-dummy-filler"
DUMMY_PASSWORD_HASH = (
    "$2b$12$K/ObcsueH8cL2HqTr5QQ8OzMIXT9CH4opE.q/s9QH9GCIvxhy1ap2"
)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False