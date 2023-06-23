from typing import Any, Optional

from fastapi.openapi.models import HTTPBase as HTTPBaseModel
from fastapi.openapi.models import HTTPBearer as HTTPBearerModel
from starlette.requests import Request

from .base import AuthenticationException, AuthenticationScheme


class InvalidAuthenticationHeaderException(AuthenticationException):
    pass


class HeaderMissingException(InvalidAuthenticationHeaderException):
    pass


class HeaderAuth(AuthenticationScheme):
    def __init__(
        self,
        *args,
        scheme: str = "raw",
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
        header_key="Authorization",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.header_key = header_key
        self.model = HTTPBaseModel(scheme=scheme, description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> str:
        authorization = request.headers.get(self.header_key)
        if authorization is None:
            raise HeaderMissingException(f"{self.header_key} header is missing")

        return authorization


class InvalidBearerSchemeException(InvalidAuthenticationHeaderException):
    pass


class BearerAuth(HeaderAuth):
    DEFAULT_SCHEMES = ["bearer"]

    def __init__(
        self,
        *args,
        bearer_schemes: list[str] | None = None,
        scheme: str = "bearer",
        **kwargs,
    ) -> None:
        super().__init__(*args, scheme=scheme, **kwargs)
        self.bearer_schemes = bearer_schemes or self.__class__.DEFAULT_SCHEMES

    async def __call__(self, request: Request) -> str:
        header_value = await super().__call__(request)
        scheme, _, param = header_value.partition(" ")

        if scheme.lower() not in self.bearer_schemes:
            raise InvalidBearerSchemeException(
                f"Scheme {scheme} not recognized. Valid schemes are: {self.bearer_schemes}",
                scheme=scheme,
            )

        return param
