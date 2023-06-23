from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from .base import AuthenticationException

try:
    from rich import traceback as rich_traceback
    from rich.console import Console

    def print_exc(exc: Exception):
        tb = rich_traceback.Traceback.from_exception(type(exc), exc, exc.__traceback__)
        c = Console().print(tb)

except ImportError:
    print_exc = print  # type: ignore


def handle_authentication_exception(request: Request, exc: AuthenticationException):
    print_exc(exc)
    return JSONResponse(
        {"detail": str(exc) or "Authentication Failed"},
        status_code=exc.status_code,
    )


DEFAULT_EXCEPTION_HANDLERS = {
    AuthenticationException: handle_authentication_exception,
}


def add_default_exception_handlers(app: Starlette):
    for cls, handler in DEFAULT_EXCEPTION_HANDLERS.items():
        app.add_exception_handler(cls, handler)
