from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from decouple import config

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("ALGORITHM")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden"
        )
    return current_user

# from fastapi import Depends, HTTPException, Request
# from auth.auth_bearer import JWTBearer
# from auth.auth_handler import decodeJWT

# def get_current_user(request: Request, token: str = Depends(JWTBearer())):
#     payload = decodeJWT(token)
#     if payload is None:
#         raise HTTPException(status_code=401, detail="Invalid authentication credentials")
#     return payload

# def get_admin_user(current_user: dict = Depends(get_current_user)):
#     if current_user["role"] != "admin":
#         raise HTTPException(status_code=403, detail="Operation forbidden")
#     return current_user
