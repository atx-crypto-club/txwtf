from datetime import datetime, timedelta
from typing import Optional

from pydantic import EmailStr

from sqlmodel import SQLModel, Field

from txwtf.core.model import User


class PostSchema(SQLModel):
    id: int = Field(default=None)
    title: str = Field(...)
    content: str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Hello, World",
                "content": "Test post",
            }
        }


class UserSchema(SQLModel):
    fullname: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {
                "fullname": "Joe Rivera",
                "email": "j@jriv.us",
                "password": "password1234",
            }
        }


class UserLoginSchema(SQLModel):
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {"email": "j@jriv.us", "password": "password1234"}
        }


class ResponseSchema(SQLModel):
    message: Optional[str] = None
    error: Optional[int] = 1 #ErrorCode.NoError
    data: dict = Field(...)


class Registration(SQLModel):
    username: str
    password: str
    verify_password: str
    name: str
    email: EmailStr

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user",
                "email": "user@example.com",
                "password": "passWord1234@",
                "verify_password": "password1234@",
                "name": "Mr User",
            }
        }


class Login(SQLModel):
    username: str
    password: str
    expire_delta: timedelta

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user",
                "password": "passWord1234@",
                "expire_delta": 3600,
            }
        }


class LoginResponse(SQLModel):
    user: User
    expires: datetime
    token: str
    session_uuid: str
