from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
import logging
from typing import Union, List
from typing_extensions import Annotated

from decouple import config

from fastapi import APIRouter, FastAPI, Body, Depends, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.ext.asyncio import AsyncEngine

from txwtf.core import (
    gen_secret,
    decode_jwt,
    authorized_session_verify,
    register_user,
    set_setting,
    request_compat,
    execute_login,
    execute_logout,
    get_user,
    authorized_sessions,
)
from txwtf.core.db import get_engine, init_db, get_session
from txwtf.core.defaults import DEFAULT_JWT_ALGORITHM, CORS_ORIGINS
from txwtf.core.codes import ErrorCode
from txwtf.core.errors import TXWTFError
from txwtf.core.model import User, AuthorizedSession
from txwtf.api.model import (
    ResponseSchema,
    Registration,
    Login,
    LoginResponse,
)
from txwtf.version import version

import uvicorn


logger = logging.getLogger(__name__)


class JWTBearer(HTTPBearer):
    def __init__(
        self,
        engine: AsyncEngine,
        jwt_secret: str,
        jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
        auto_error: bool = True,
    ):
        super(JWTBearer, self).__init__(auto_error=auto_error)
        self._engine = engine
        self._jwt_secret = jwt_secret
        self._jwt_algorithm = jwt_algorithm

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)

        if not credentials.scheme == "Bearer":
            raise HTTPException(
                status_code=403, detail="Invalid authentication scheme."
            )

        try:
            return await self.verify_jwt(credentials.credentials)
        except TXWTFError as e:
            code, msg = e.args
            raise HTTPException(
                status_code=403,
                detail="{} ({})".format(msg, code)
            )

    async def verify_jwt(self, jwtoken: str):
        payload = decode_jwt(
            self._jwt_secret,
            self._jwt_algorithm,
            jwtoken
        )
        async with get_session(self._engine) as session:
            await authorized_session_verify(
                session,
                payload["uuid"],
                self._jwt_secret)
        return payload


@contextmanager
def map_txwtf_errors(status_code=400):
    try:
        yield
    except TXWTFError as e:
        code, msg = e.args
        raise HTTPException(
            status_code=status_code,
            detail="{} ({})".format(msg, code)
        )


def get_user_router(
    engine: AsyncEngine,
    jwt_secret: str = None,
    jwt_algorithm: str = None
) -> APIRouter:
    router = APIRouter(
        tags=["user"],
        responses={
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            404: {"description": "Not found"},
            403: {"description": "Access denied"},
        },
    )

    @router.post(
        "/register",
        #tags=["auth"],
        response_model=User
    )
    async def register(
        user: Registration,
        request: Request,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ):
        with map_txwtf_errors():
            async with get_session(engine) as session:
                return await register_user(
                    session,
                    user.username,
                    user.password,
                    user.verify_password,
                    user.name,
                    user.email,
                    request_compat(request, user_agent),
                )

    @router.post(
        "/login",
        # tags=["auth"],
        response_model=LoginResponse
    )
    async def login(
        login: Login,
        request: Request,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ):
        with map_txwtf_errors(401):
            async with get_session(engine) as session:
                user, token_payload = await execute_login(
                    session,
                    login.username,
                    login.password,
                    jwt_secret,
                    jwt_algorithm,
                    request_compat(request, user_agent),
                    login.expire_delta,
                )
        expires = datetime.fromtimestamp(token_payload["expires"])
        return LoginResponse(
            user=user,
            expires=expires,
            token=token_payload["token"],
            session_uuid=token_payload["uuid"],
        )

    @router.get(
        "/logout",
        # tags=["auth"],
        response_model=ResponseSchema,
    )
    async def logout(
        request: Request,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ],
        user_agent: Annotated[Union[str, None], Header()] = None,
        all: bool = False,
    ):
        with map_txwtf_errors(401):
            async with get_session(engine) as session:
                user_id = token_payload["user_id"]
                user: User = await get_user(session, user_id)
                if not all:
                    await execute_logout(
                        session,
                        token_payload["uuid"],
                        jwt_secret,
                        request_compat(request, user_agent),
                        user,
                    )
                else:
                    sessions = await authorized_sessions(
                        session,
                        user_id,
                        True,
                        jwt_secret
                    )
                    for auth_sess in sessions:
                        await execute_logout(
                            session,
                            auth_sess.uuid,
                            jwt_secret,
                            request_compat(request, user_agent),
                            user,
                        )

        return ResponseSchema(message="Successfully logged out")

    @router.get(
        "/sessions",
        # tags=["auth"],
        response_model=List[AuthorizedSession],
    )
    async def get_sessions(
        verified_only: bool = True,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ):
        with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await authorized_sessions(
                    session,
                    token_payload["user_id"],
                    verified_only,
                    jwt_secret
                )

    return router


description = """
# txwtf api
A library for backend services. Provides basic user authentication,
authorization and other common functionality.

"""


def create_app(
    jwt_secret: str = None,
    jwt_algorithm: str = None,
    db_url: str = None,
    origins: list = [],
) -> FastAPI:

    # TODO: use pydantic settings and dotenv instead, remove decouple
    if jwt_algorithm is None:
        jwt_algorithm = config("TXWTF_API_JWT_ALGO", default=DEFAULT_JWT_ALGORITHM)
    if jwt_secret is None:
        jwt_secret = config("TXWTF_API_JWT_SECRET", default=gen_secret())
    if db_url is None:
        db_url = config("TXWTF_API_DB_URL", default="sqlite+aiosqlite://")

    engine = get_engine(db_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Launching API")
        await init_db(engine)  # TODO: flag for init or something
        async with get_session(engine) as session:
            # Disable email deliverability verification for now to
            # help with testing
            await set_setting(session, "email_validate_deliv_enabled", 0)
        yield
        logger.info("Shutting down API")

    origins.extend(CORS_ORIGINS)

    app = FastAPI(
        lifespan=lifespan,
        title="txwtf",
        summary="A library for backend services.",
        version=version,
        description=description,
        contact={
            "name": "Joe Rivera",
            "url": "https://jriv.us",
            "email": "j@jriv.us",
        },
        license_info={
            "name": "MIT",
            "url": "https://opensource.org/license/mit",
        },
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", tags=["root"])
    async def read_root() -> ResponseSchema:
        return ResponseSchema(message="txwtf v{}".format(version))

    # **** API entry points ****

    app.include_router(
        get_user_router(engine, jwt_secret, jwt_algorithm),
        prefix="/user",
        # tags=["user"]
    )

    return app


def launch(host="0.0.0.0", port=8081):
    """
    Launch the txwtf.api backend using uvicorn.
    """
    uvicorn.run(
        "txwtf.api:create_app",
        host=host,
        port=port,
        reload=True,
        factory=True
    )
