import uuid
from typing import Annotated, TypeAlias

from fastapi import Body, FastAPI, Security, security
from pydantic import BaseModel

from fast_authentication import (
    JWTAccessBearer,
    JWTRefreshBearer,
    add_default_exception_handlers,
)

app = FastAPI()
add_default_exception_handlers(app)

access_scheme = JWTAccessBearer(secret_key="123")
refresh_scheme = JWTRefreshBearer(secret_key="123")
AccessToken: TypeAlias = Annotated[dict, Security(access_scheme)]
RefreshToken: TypeAlias = Annotated[dict, Security(refresh_scheme)]


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    id: str
    access_token: str
    refresh_token: str


@app.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest = Body()):
    access_token = access_scheme.create_access_token(body.username)
    refresh_token = refresh_scheme.create_refresh_token(body.username)

    return LoginResponse(
        id=str(uuid.uuid4()), access_token=access_token, refresh_token=refresh_token
    )


@app.get("/protected")
async def protected(auth: AccessToken):
    return "Access Granted"


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str


@app.get("/refresh")
async def refresh(auth: RefreshToken):
    access_token = access_scheme.create_access_token(auth["subject"])
    refresh_token = refresh_scheme.create_refresh_token(auth["subject"])

    return LoginResponse(
        id=str(uuid.uuid4()), access_token=access_token, refresh_token=refresh_token
    )
