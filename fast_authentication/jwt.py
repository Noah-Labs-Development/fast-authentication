import uuid
from datetime import datetime, timedelta
from typing import Any, Literal, Sequence, Type

import jose.exceptions as jose_exc
from jose import jwt
from jose.constants import ALGORITHMS
from pydantic import BaseModel
from starlette.requests import Request

from .base import AuthenticationException
from .header import BearerAuth


class JWTException(AuthenticationException):
    def __init__(self, msg="JWT invalid", *args, **kwargs) -> None:
        super().__init__(msg, *args, **kwargs)


class ExpiredSignatureError(JWTException):
    def __init__(self, msg: str = "JWT signature expired", *args, **kwargs) -> None:
        super().__init__(msg, *args, **kwargs)


class JwtCore:
    def __init__(
        self,
        secret_key: str,
        algorithms: Sequence[str] | None = None,
        access_expires_delta: timedelta | None = None,
        refresh_expires_delta: timedelta | None = None,
        options: dict | None = None,
    ) -> None:
        self.secret_key = secret_key
        self.algorithms = algorithms or [ALGORITHMS.HS256]
        self.access_expires_delta = access_expires_delta or timedelta(minutes=15)
        self.refresh_expires_delta = refresh_expires_delta or timedelta(days=31)
        self.options = options

    def decode(self, token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=self.algorithms,
                options=self.options,
            )
            return payload
        except jose_exc.ExpiredSignatureError as exc:
            raise ExpiredSignatureError() from exc
        except jose_exc.JWTError as exc:
            raise JWTException() from exc

    def generate_payload(
        self,
        token_type: Literal["access"] | Literal["refresh"],
        expires_delta: timedelta,
        subject: str,
        unique_identifier: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        unique_identifier = unique_identifier or str(uuid.uuid4())
        now = datetime.utcnow()
        payload = {
            "type": token_type,  # 'access' or 'refresh' token
            "exp": now + expires_delta,  # expire time
            "iat": now,  # creation time
            "jti": unique_identifier,  # uuid
            "subject": subject,  # main subject
        }
        if claims:
            payload.update(claims)

        return payload

    def create_access_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        unique_identifier: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> str:
        to_encode = self.generate_payload(
            "access",
            expires_delta or self.access_expires_delta,
            subject,
            unique_identifier,
            claims,
        )
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithms[0])

    def create_refresh_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        unique_identifier: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> str:
        to_encode = self.generate_payload(
            "refresh",
            expires_delta or self.refresh_expires_delta,
            subject,
            unique_identifier,
            claims,
        )
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithms[0])


class JWTAccessBearer(BearerAuth):
    def __init__(
        self,
        *args,
        secret_key: str,
        algorithms: Sequence[str] | None = None,
        access_expires_delta: timedelta | None = None,
        jwt_options: dict | None = None,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.jwt = JwtCore(
            secret_key,
            algorithms=algorithms,
            access_expires_delta=access_expires_delta,
            options=jwt_options,
        )

    async def __call__(self, request: Request) -> dict[str, Any]:
        encoded_token = await super().__call__(request)
        decoded_token = self.jwt.decode(encoded_token)
        decoded_token["__encoded"] = encoded_token
        return decoded_token

    def create_access_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        unique_identifier: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> str:
        return self.jwt.create_access_token(
            subject, expires_delta, unique_identifier, claims
        )


class JWTRefreshBearer(BearerAuth):
    def __init__(
        self,
        *args,
        secret_key: str,
        algorithms: Sequence[str] | None = None,
        refresh_expires_delta: timedelta | None = None,
        jwt_options: dict | None = None,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.jwt = JwtCore(
            secret_key,
            algorithms=algorithms,
            refresh_expires_delta=refresh_expires_delta,
            options=jwt_options,
        )

    async def __call__(self, request: Request) -> dict[str, Any]:
        encoded_token = await super().__call__(request)
        decoded_token = self.jwt.decode(encoded_token)
        decoded_token["__encoded"] = encoded_token
        return decoded_token

    def create_refresh_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        unique_identifier: str | None = None,
        claims: dict[str, Any] | None = None,
    ) -> str:
        return self.jwt.create_refresh_token(
            subject, expires_delta, unique_identifier, claims
        )
