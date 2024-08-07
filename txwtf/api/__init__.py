from contextlib import asynccontextmanager

from fastapi import FastAPI, Body, Depends

from txwtf.api.auth import init_auth_config, sign_jwt, JWTBearer
from txwtf.api.db import get_engine, init_db, get_session
from txwtf.api.model import PostSchema, UserSchema, UserLoginSchema
from txwtf.version import version


posts = [{"id": 1, "title": "Pancake", "content": "Lorem Ipsum ..."}]

users = []


def create_app(db_url: str = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_auth_config()
        yield

    app = FastAPI(lifespan=lifespan)

    @app.get("/", tags=["root"])
    async def read_root() -> dict:
        return {"message": "txwtf v{}".format(version)}

    @app.get("/posts", tags=["posts"])
    async def get_posts() -> dict:
        return {"data": posts}

    @app.get("/posts/{id}", tags=["posts"])
    async def get_single_post(id: int) -> dict:
        if id > len(posts):
            return {"error": "No such post with the supplied ID."}

        for post in posts:
            if post["id"] == id:
                return {"data": post}

    @app.post("/posts", dependencies=[Depends(JWTBearer())], tags=["posts"])
    async def add_post(post: PostSchema) -> dict:
        post.id = len(posts) + 1
        posts.append(post.dict())
        return {"data": "post added."}

    @app.post("/user/signup", tags=["user"])
    async def create_user(user: UserSchema = Body(...)):
        users.append(
            user
        )  # replace with db call, making sure to hash the password first
        return sign_jwt(user.email)

    def check_user(data: UserLoginSchema):
        for user in users:
            if user.email == data.email and user.password == data.password:
                return True
        return False

    @app.post("/user/login", tags=["user"])
    async def user_login(user: UserLoginSchema = Body(...)):
        if check_user(user):
            return sign_jwt(user.email)
        return {"error": "Wrong login details!"}

    return app
