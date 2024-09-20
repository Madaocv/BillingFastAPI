from fastapi import FastAPI, HTTPException, Request
from models import User, init_db
from contextlib import asynccontextmanager
from models import init_db
from pprint import pformat


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)


@app.post("/register")
async def register(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    full_name = data.get("full_name")
    if await User.get_user_id(username):
        raise HTTPException(status_code=400, detail="Username already registered")
    await User.create(username, password, full_name)
    return {"message": "User registered successfully"}


@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    if not await User.authenticate(username, password):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    access_token = User.create_access_token(username=username)
    refresh_token = User.create_refresh_token(username=username)

    user_id = await User.get_user_id(username)

    await User.save_tokens(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh-token")
async def refresh_token(request: Request):
    try:
        data = await request.json()
        refresh_token = data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token is missing")
        username = await User.verify_refresh_token(refresh_token)
        if not username:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    new_access_token = User.create_access_token(username=username)
    user_id = await User.get_user_id(username)
    await User.update_access_token(
        user_id=user_id,
        new_access_token=new_access_token
        )
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }
