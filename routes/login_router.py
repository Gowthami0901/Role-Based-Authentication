from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from pymongo import MongoClient
from bcrypt import checkpw
from auth.auth_handler import signJWT
from config.db import user_collection  

login_router = APIRouter(prefix="/api/v1/login", tags=['Login'])

# Define the request model for login
class LoginRequest(BaseModel):
    email: str
    password: str

def verify_user(email: str, password: str) -> dict:
    user = user_collection.find_one({"email": email})
    if user and checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return user
    return None

@login_router.post("/token")
async def login_for_access_token(request: LoginRequest):
    user = verify_user(request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    role = user.get("role", "user")  # Default to "user" if role is not set
    access_token = signJWT(user_id=str(user["_id"]), role=role)

    return {
        "access_token": access_token["access_token"],
        "token_type": access_token["token_type"]
    }
