
import jwt
from decouple import config
from datetime import datetime, timedelta
from fastapi import Request, HTTPException
from fastapi import status

SECRET_KEY = config('secret')  # Ensure to use 'SECRET_KEY' from your environment variables
ALGORITHM = 'HS256'

def signJWT(user_id: str, role: str):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "role": role
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer"
    }

def decodeJWT(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
