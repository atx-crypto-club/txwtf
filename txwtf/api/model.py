from typing import Optional

#from pydantic import BaseModel, Field, EmailStr
from pydantic import EmailStr

from sqlmodel import SQLModel, Field


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
