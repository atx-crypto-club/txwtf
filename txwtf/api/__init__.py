from contextlib import asynccontextmanager
import logging

from decouple import config

from fastapi import APIRouter, FastAPI, Body, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from txwtf.core import gen_secret
from txwtf.core.defaults import DEFAULT_JWT_ALGORITHM, CORS_ORIGINS
from txwtf.core.auth import sign_jwt
from txwtf.core.codes import ErrorCode
from txwtf.core.model import PostSchema, UserSchema, UserLoginSchema, ResponseSchema
from txwtf.version import version

import uvicorn


class JWTBearer(HTTPBearer):
    def __init__(
        self,
        jwt_secret: str,
        jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
        auto_error: bool = True,
    ):
        super(JWTBearer, self).__init__(auto_error=auto_error)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        valid: bool = False

        try:
            payload = decode_jwt(self.jwt_secret, self.jwt_algorithm, jwtoken)
            payload = payload if payload["expires"] >= time.time() else None
        except:
            payload = None
        if payload is not None:
            valid = True

        return valid


logger = logging.getLogger(__name__)


posts = [{"id": 1, "title": "Pancake", "content": "Lorem Ipsum ..."}]

users = []


def get_test_router(
        jwt_secret: str = None, jwt_algorithm: str = None
) -> APIRouter:
    router = APIRouter(
        #tags=["test"],
        responses={404: {"description": "Not found"}},
    )

    @router.get("/posts", tags=["posts"])
    async def get_posts() -> ResponseSchema:
        return ResponseSchema(data={"posts":posts})

    @router.get("/posts/{id}", tags=["posts"])
    async def get_single_post(id: int) -> ResponseSchema:
        if id > len(posts):
            return ResponseSchema(
                message="No such post with the supplied ID.",
                error=ErrorCode.GenericError)

        for post in posts:
            if post["id"] == id:
                return ResponseSchema(data={"post": post})

    @router.post(
        "/posts",
        dependencies=[Depends(JWTBearer(jwt_secret, jwt_algorithm))],
        tags=["posts"],
    )
    async def add_post(post: PostSchema) -> ResponseSchema:
        post.id = len(posts) + 1
        posts.append(post.dict())
        return ResponseSchema(message="post added.")

    @router.post("/user/signup", tags=["user"])
    async def create_user(user: UserSchema = Body(...)):
        users.append(
            user
        )  # replace with db call, making sure to hash the password first
        return ResponseSchema(
            data=sign_jwt(jwt_secret, jwt_algorithm, user.email))

    def check_user(data: UserLoginSchema):
        for user in users:
            if user.email == data.email and user.password == data.password:
                return True
        return False

    @router.post("/user/login", tags=["user"])
    async def user_login(user: UserLoginSchema = Body(...)):
        if check_user(user):
            return ResponseSchema(
                data=sign_jwt(jwt_secret, jwt_algorithm, user.email))
        return ResponseSchema(
            message="Wrong login details!",
            error=ErrorCode.GenericError)

    return router


def create_app(
    jwt_secret: str = None,
    jwt_algorithm: str = None,
    db_url: str = None,
    origins: list = []
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Launching API")
        yield
        logger.info("Shutting down API")

    if jwt_algorithm is None:
        jwt_algorithm = config("TXWTF_API_JWT_ALGO", default=DEFAULT_JWT_ALGORITHM)
    if jwt_secret is None:
        jwt_secret = config("TXWTF_API_JWT_SECRET", default=gen_secret())
    origins.extend(CORS_ORIGINS)

    app = FastAPI(lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", tags=["root"])
    async def read_root() -> dict:
        return {"message": "txwtf v{}".format(version)}
    
    app.include_router(
        get_test_router(jwt_secret, jwt_secret),
        prefix="/test",
        tags=["jwt demo"])


    return app


def launch(host="0.0.0.0", port=8081):
    """
    Launch the txwtf.api backend using uvicorn.
    """
    uvicorn.run("txwtf.api:create_app", host=host, port=port, reload=True, factory=True)
