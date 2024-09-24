from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
import logging
from typing import Union, List, Dict, Optional
from typing_extensions import Annotated

from decouple import config

from fastapi import (
    APIRouter,
    FastAPI,
    Body, 
    Depends, 
    HTTPException, 
    Request, 
    Header
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.ext.asyncio import AsyncEngine

import txwtf.core
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
from txwtf.core.codes import ErrorCode, PermissionCode
from txwtf.core.errors import TXWTFError
from txwtf.core.model import (
    User,
    AuthorizedSession,
    Group,
    GroupAssociation,
    GroupPermission,
)
from txwtf.api.model import (
    ResponseSchema,
    Registration,
    Login,
    LoginResponse,
)
from txwtf.version import version

import uvicorn


logger = logging.getLogger(__name__)


def copy_doc(copy_func):
    """Copies the doc string of the given function to another. 
    This function is intended to be used as a decorator.

    .. code-block:: python3

        def foo():
            '''This is a foo doc string'''
            ...

        @copy_doc(foo)
        def bar():
            ...
    """

    def wrapped(func):
        func.__doc__ = copy_func.__doc__
        return func

    return wrapped


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


@asynccontextmanager
async def map_txwtf_errors(status_code=400):
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
        response_model=User
    )
    @copy_doc(register_user)
    async def register(
        user: Registration,
        request: Request,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ):
        async with map_txwtf_errors():
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
        response_model=LoginResponse
    )
    @copy_doc(execute_login)
    async def login(
        login: Login,
        request: Request,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ):
        async with map_txwtf_errors(401):
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

    @router.post(
        "/logout",
        response_model=ResponseSchema,
    )
    @copy_doc(execute_logout)
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
        async with map_txwtf_errors(401):
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
        response_model=List[AuthorizedSession],
    )
    @copy_doc(authorized_sessions)
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
        async with map_txwtf_errors(401):
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
    
    @router.get(
        "/",
        response_model=Union[User, List[User]],
    )
    @copy_doc(txwtf.core.get_user)
    async def get_user(
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> Union[User, List[User]]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_user(
                    session,
                    user_id,
                    username,
                )
            
    @router.get(
        "/groups",
        response_model=List[Group],
    )
    @copy_doc(txwtf.core.get_users_groups)
    async def get_users_groups(
        user_id: int,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> List[Group]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_users_groups(
                    session,
                    user_id,
                )

    return router


def get_group_router(
    engine: AsyncEngine,
    jwt_secret: str = None,
    jwt_algorithm: str = None
) -> APIRouter:
    router = APIRouter(
        tags=["group"],
        responses={
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            404: {"description": "Not found"},
            403: {"description": "Access denied"},
        },
    )

    @router.get(
        "/all",
        response_model=List[Group],
    )
    @copy_doc(txwtf.core.get_groups)
    async def get_groups(
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> List[Group]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_groups(session)
            
    @router.get(
        "/",
        response_model=Union[Group, List[Group]],
    )
    @copy_doc(txwtf.core.get_group)
    async def get_group(
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> Union[Group, List[Group]]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_group(
                    session,
                    group_id,
                    group_name,
                )
            
    @router.get(
        "/has",
        response_model=bool,
    )
    @copy_doc(txwtf.core.has_group)
    async def has_group(
        group_id: Optional[int] = None,
        group_name: Optional[str] = None,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> bool:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.has_group(
                    session,
                    group_id,
                    group_name,
                )

    @router.post(
        "/",
        response_model=Group,
    )
    @copy_doc(txwtf.core.create_group)
    async def create_group(
        request: Request,
        group_name: str,
        description: Optional[str] = None,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> Group:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.create_group(
                    session,
                    group_name,
                    description,
                    request_compat(request, user_agent)
                )
            
    @router.delete(
        "/",
        response_model=None,
    )
    @copy_doc(txwtf.core.remove_group)
    async def remove_group(
        request: Request,
        group_name: str,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> None:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.remove_group(
                    session,
                    group_name,
                    request_compat(request, user_agent)
                )

    @router.get(
        "/contains",
        response_model=bool,
    )
    @copy_doc(txwtf.core.is_user_in_group)
    async def is_user_in_group(
        request: Request,
        ga: GroupAssociation,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> bool:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.is_user_in_group(
                    session,
                    ga.group_id,
                    ga.user_id,
                    request_compat(request, user_agent)
                )
            
    @router.post(
        "/user",
        response_model=GroupAssociation,
    )
    @copy_doc(txwtf.core.add_user_to_group)
    async def add_user_to_group(
        request: Request,
        ga: GroupAssociation,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> GroupAssociation:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.add_user_to_group(
                    session,
                    ga.group_id,
                    ga.user_id,
                    request_compat(request, user_agent)
                )

    @router.delete(
        "/user",
        response_model=None,
    )
    @copy_doc(txwtf.core.remove_user_from_group)
    async def remove_user_from_group(
        request: Request,
        ga: GroupAssociation,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> None:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.remove_user_from_group(
                    session,
                    ga.group_id,
                    ga.user_id,
                    request_compat(request, user_agent)
                )

    @router.get(
        "/user",
        response_model=List[int],
    )
    @copy_doc(txwtf.core.get_groups_users)
    async def get_groups_users(
        request: Request,
        group_id: int,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> List[int]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_groups_users(
                    session,
                    group_id,
                    request_compat(request, user_agent)
                )

    @router.get(
        "/desc",
        response_model=str,
    )
    @copy_doc(txwtf.core.get_group_description)
    async def get_group_description(
        group_name: str,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
    ) -> List[int]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_group_description(
                    session,
                    group_name,
                )
            
    @router.put(
        "/desc",
        response_model=str,
    )
    @copy_doc(txwtf.core.set_group_description)
    async def set_group_description(
        request: Request,
        group_name: str,
        desc: str,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> List[int]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.set_group_description(
                    session,
                    group_name,
                    desc,
                    request_compat(request, user_agent)
                )

    return router


def get_permissions_router(
    engine: AsyncEngine,
    jwt_secret: str = None,
    jwt_algorithm: str = None
) -> APIRouter:
    router = APIRouter(
        tags=["perms"],
        responses={
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            404: {"description": "Not found"},
            403: {"description": "Access denied"},
        },
    )

    @router.get(
        "/user",
        response_model=List[PermissionCode],
    )
    @copy_doc(txwtf.core.get_users_permissions)
    async def get_users_permissions(
        request: Request,
        user_id: int,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> List[PermissionCode]:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.get_users_permissions(
                    session,
                    user_id,
                    request_compat(request, user_agent)
                )

    @router.post(
        "/",
        response_model=GroupPermission,
    )
    @copy_doc(txwtf.core.add_group_permission)
    async def add_group_permission(
        request: Request,
        group_id: int,
        permission_code: PermissionCode,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> GroupPermission:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.add_group_permission(
                    session,
                    group_id,
                    permission_code,
                    request_compat(request, user_agent)
                )

    @router.delete(
        "/",
        response_model=None,
    )
    @copy_doc(txwtf.core.remove_group_permission)
    async def remove_group_permission(
        request: Request,
        group_id: int,
        permission_code: PermissionCode,
        token_payload: Annotated[
            JWTBearer, Depends(
                JWTBearer(
                    engine,
                    jwt_secret,
                    jwt_algorithm
                )
            )
        ] = None,
        user_agent: Annotated[Union[str, None], Header()] = None,
    ) -> None:
        async with map_txwtf_errors(401):
            async with get_session(
                engine,
                user_id=token_payload["user_id"]
            ) as session:
                return await txwtf.core.remove_group_permission(
                    session,
                    group_id,
                    permission_code,
                    request_compat(request, user_agent)
                )

    @router.get(
        "/codes",
        response_model=Dict[str, int],
    )
    @copy_doc(txwtf.core.get_permission_codes)
    async def get_groups() -> Dict[str, int]:
        return txwtf.core.get_permission_codes()

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

    start_time = datetime.utcnow()

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
        return ResponseSchema(message="txwtf v{} - {}".format(
            version, start_time))

    # **** API entry points ****

    app.include_router(
        get_user_router(engine, jwt_secret, jwt_algorithm),
        prefix="/user",
    )

    app.include_router(
        get_group_router(engine, jwt_secret, jwt_algorithm),
        prefix="/group",
    )

    app.include_router(
        get_permissions_router(engine, jwt_secret, jwt_algorithm),
        prefix="/perms",
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
