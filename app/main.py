"""FastAPI application: health, register, login, protected profile."""
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import db
from .config import Settings, get_settings
from .logging_conf import log_event, setup_logging
from .schemas import LoginRequest, ProfileResponse, RegisterRequest, TokenResponse
from .security import create_token, decode_token, hash_password, verify_password

logger = setup_logging()
bearer = HTTPBearer(auto_error=False)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.init_db(settings)
        yield

    # debug is hard-wired off; interactive docs are only exposed outside production.
    app = FastAPI(
        title="Secure CI/CD Demo API",
        debug=False,
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.middleware("http")
    async def secure_headers_and_logging(request: Request, call_next):
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:  # last-resort handler so headers + generic 500 still apply
            log_event(logger, "unhandled_error", path=request.url.path, error_type=type(exc).__name__)
            response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        log_event(
            logger,
            "request",
            method=request.method,
            path=request.url.path,  # path only: query strings may contain secrets
            status=response.status_code,
            ms=round((time.perf_counter() - start) * 1000, 1),
        )
        return response

    # ---- centralized error handling: generic messages, no internals ----
    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        # Report WHICH field failed, never echo the submitted value (could be a password).
        errors = [{"field": ".".join(str(p) for p in e["loc"][1:]), "issue": e["type"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Invalid input", "errors": errors})

    @app.exception_handler(HTTPException)
    async def http_handler(_: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)

    def current_user(
        creds: HTTPAuthorizationCredentials | None = Depends(bearer),
        s: Settings = Depends(get_settings),
    ) -> str:
        unauthorized = HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"}
        )
        if creds is None:
            raise unauthorized
        username = decode_token(creds.credentials, s)
        if username is None or db.get_user(s, username) is None:
            raise unauthorized
        return username

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/register", status_code=status.HTTP_201_CREATED)
    def register(body: RegisterRequest, s: Settings = Depends(get_settings)):
        if not db.create_user(s, body.username, body.email, hash_password(body.password)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Username or email already in use")
        log_event(logger, "user_registered", username=body.username)
        return {"username": body.username}

    @app.post("/login", response_model=TokenResponse)
    def login(body: LoginRequest, s: Settings = Depends(get_settings)):
        user = db.get_user(s, body.username)
        ok = verify_password(user["password_hash"] if user else None, body.password)
        if not (user and ok):
            # Same message for "no such user" and "wrong password" (no user enumeration).
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"}
            )
        return TokenResponse(access_token=create_token(body.username, s))

    @app.get("/profile", response_model=ProfileResponse)
    def profile(username: str = Depends(current_user), s: Settings = Depends(get_settings)):
        user = db.get_user(s, username)
        return ProfileResponse(username=user["username"], email=user["email"])

    return app


app = create_app()
