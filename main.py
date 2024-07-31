# main.py
import uvicorn
from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse
from fastapi import FastAPI
from routes.user import user
from fastapi.middleware.cors import CORSMiddleware
from exceptions.exceptions import InvalidUserException # from routes.login_router import login_router
from routes.password_reset import password_reset_router
from routes.login_router import login_router

app = FastAPI(title="User Management")

origins = [
    "http://localhost",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.exception_handler(InvalidUserException)
async def invalid_user_handler(request: Request, exc: InvalidUserException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

app.include_router(user)
app.include_router(login_router)
app.include_router(password_reset_router)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
