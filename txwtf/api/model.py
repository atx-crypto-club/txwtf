from datetime import datetime
from typing import Optional

# from pydantic import BaseModel, Field, EmailStr
from pydantic import EmailStr

from sqlmodel import SQLModel, Column, Field
from sqlalchemy import DateTime, func


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


class GlobalSettings(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    var: str
    val: str
    parent_id: Optional[int] = None
    user_id: Optional[int] = None  # track user that created this setting
    created_time: datetime = Field(default_factory=lambda: datetime.now(datetime.UTC))
    modified_time: Optional[datetime] = Field(
        sa_column=Column(DateTime(), onupdate=func.now())
    )
    accessed_time: datetime = Field(default_factory=lambda: datetime.now(datetime.UTC))
