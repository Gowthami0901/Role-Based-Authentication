from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from models.user import User, UpdateUser
from config.db import db, user_collection
from schemas.user import userEntity, usersEntity
from bcrypt import hashpw, gensalt
from exceptions.exceptions import InvalidUserException
from auth.auth_bearer import JWTBearer
from auth.auth_handler import decodeJWT
from bson import ObjectId
import logging

user = APIRouter(prefix="/api/v1/user", tags=['User'])

def get_next_sequence_value(sequence_name):
    seq = db.counters.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"sequence_value": 1}},
        upsert=True,
        return_document=True
    )
    return seq["sequence_value"]

def get_current_user(token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token or expired token.")
    
    user_id = payload.get("sub")
    user = user_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user

logger = logging.getLogger("uvicorn")

@user.get('/users', dependencies=[Depends(JWTBearer())])
async def find_all_users(current_user: dict = Depends(get_current_user)):
    # Check if the current user is an admin
    if current_user["role"] == "admin":
        # Fetch only users with role 'user'
        users = user_collection.find({"role": "user"})
        return JSONResponse(status_code=status.HTTP_200_OK, content=usersEntity(users))
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can access this resource."
        )

@user.post('/')
async def create_user(user: User):
    try:
        existing_user = user_collection.find_one({"email": user.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        user_dict = user.dict()
        user_dict['id'] = get_next_sequence_value('userid')   # Assign sequential ID
        user_dict['password'] = hashpw(user.password.encode('utf-8'), gensalt()).decode('utf-8')
        user_collection.insert_one(user_dict)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=userEntity(user_dict))
    
    except InvalidUserException as e:
        raise e
    except Exception as e:
        raise InvalidUserException(detail=str(e))

@user.get('/{id}', dependencies=[Depends(get_current_user)])
async def get_user(id: int, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin" and id != current_user.get("id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden"
        )
    
    user = user_collection.find_one({"id": id})
    if user:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
        return JSONResponse(status_code=status.HTTP_200_OK, content=userEntity(user))
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {id} not found"
        )
    
    
@user.put('/{id}', dependencies=[Depends(get_current_user)])
async def update_user(user_id: str, update_user: UpdateUser, current_user: dict = Depends(get_current_user)):
    # Check if the current user is an admin or the same user
    if current_user["role"] != "admin" and current_user["id"] != int(user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden. Only admins can update other users."
        )
    
    # Update the user in the database
    updated_user = {k: v for k, v in update_user.dict().items() if v is not None}
    if updated_user:
        result = user_collection.update_one({"id": int(user_id)}, {"$set": updated_user})
        if result.modified_count == 1:
            return {"message": "User updated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid fields to update"
        )

@user.delete('/{id}', dependencies=[Depends(get_current_user)])
async def delete_user(id: int, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin" and id != current_user.get("id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden"
        )
    
    result = user_collection.delete_one({"id": id})

    if result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": f"User with id {id} deleted successfully"})
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {id} not found"
        )
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user