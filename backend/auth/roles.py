from fastapi import HTTPException


def require_role(required_role):

    def checker(user):

        if user["role"] != required_role:

            raise HTTPException(
                status_code=403,
                detail="forbidden"
            )

        return user

    return checker

