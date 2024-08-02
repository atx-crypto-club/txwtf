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
                "title": "Securing FastAPI applications with JWT.",
                "content": "In this tutorial, you'll learn how to secure your application by enabling authentication using JWT. We'll be using PyJWT to sign, encode and decode JWT tokens....",
            }
        }


class UserSchema(SQLModel):
    fullname: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {
                "fullname": "Abdulazeez Abdulazeez Adeshina",
                "email": "abdulazeez@x.com",
                "password": "weakpassword",
            }
        }


class UserLoginSchema(SQLModel):
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        json_schema_extra = {
            "example": {"email": "abdulazeez@x.com", "password": "weakpassword"}
        }
