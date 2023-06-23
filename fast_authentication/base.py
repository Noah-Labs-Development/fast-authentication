from abc import abstractmethod
from typing import Any, Protocol

from fastapi.security.base import SecurityBase
from starlette.requests import Request


class AuthenticationException(Exception):
    def __init__(self, *args, status_code: int = 401, **kwargs) -> None:
        super().__init__(*args)
        self.status_code = status_code


class AuthenticationScheme(SecurityBase):
    @abstractmethod
    async def __call__(self, request: Request) -> Any:
        raise NotImplementedError()
