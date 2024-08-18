from contextlib import asynccontextmanager
import logging

from decouple import config
from fastapi import APIRouter, FastAPI, Body, Depends, HTTPException

from txwtf.core import gen_secret
from txwtf.api.auth import sign_jwt, JWTBearer
from txwtf.api.db import get_engine, init_db, get_session
from txwtf.api.model import PostSchema, UserSchema, UserLoginSchema
from txwtf.version import version

import uvicorn


logger = logging.getLogger(__name__)


DEFAULT_JWT_ALGORITHM = "HS256"


posts = [{"id": 1, "title": "Pancake", "content": "Lorem Ipsum ..."}]

users = []


def get_test_router(
        jwt_secret: str = None, jwt_algorithm: str = None
) -> APIRouter:
    router = APIRouter(
        tags=["test"],
        responses={404: {"description": "Not found"}},
    )

    @router.get("/posts", tags=["posts"])
    async def get_posts() -> dict:
        return {"data": posts}

    @router.get("/posts/{id}", tags=["posts"])
    async def get_single_post(id: int) -> dict:
        if id > len(posts):
            return {"error": "No such post with the supplied ID."}

        for post in posts:
            if post["id"] == id:
                return {"data": post}

    @router.post(
        "/posts",
        dependencies=[Depends(JWTBearer(jwt_secret, jwt_algorithm))],
        tags=["posts"],
    )
    async def add_post(post: PostSchema) -> dict:
        post.id = len(posts) + 1
        posts.append(post.dict())
        return {"data": "post added."}

    @router.post("/user/signup", tags=["user"])
    async def create_user(user: UserSchema = Body(...)):
        users.append(
            user
        )  # replace with db call, making sure to hash the password first
        return sign_jwt(user.email, jwt_secret, jwt_algorithm)

    def check_user(data: UserLoginSchema):
        for user in users:
            if user.email == data.email and user.password == data.password:
                return True
        return False

    @router.post("/user/login", tags=["user"])
    async def user_login(user: UserLoginSchema = Body(...)):
        if check_user(user):
            return sign_jwt(user.email, jwt_secret, jwt_algorithm)
        return {"error": "Wrong login details!"}

    return router


def create_app(
    jwt_secret: str = None, jwt_algorithm: str = None, db_url: str = None
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

    app = FastAPI(lifespan=lifespan)

    @app.get("/", tags=["root"])
    async def read_root() -> dict:
        return {"message": "txwtf v{}".format(version)}
    
    app.include_router(
        get_test_router(),
        prefix="/test",
        tags=["jwt demo"])


    return app


def launch(host="0.0.0.0", port=8081):
    """
    Launch the txwtf.api backend using uvicorn.
    """
    uvicorn.run("txwtf.api:create_app", host=host, port=port, reload=True, factory=True)
