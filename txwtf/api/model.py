from datetime import datetime, timedelta
from typing import Optional, Union, List

from pydantic import EmailStr

from sqlmodel import SQLModel, Field

from txwtf.core.model import User
from txwtf.core.codes import PermissionCode


class ResponseSchema(SQLModel):
    message: Optional[str] = None
    code: Optional[int] = 1  # ErrorCode.NoError
    data: Optional[dict] = None


class Registration(SQLModel):
    username: str
    password: str
    verify_password: str
    name: str
    email: EmailStr
    add_user_to_default_group: Optional[bool] = False

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user",
                "email": "user@example.com",
                "password": "passWord1234@",
                "verify_password": "passWord1234@",
                "name": "Mr User",
                "add_user_to_default_group": "true"
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


class CreateGroup(SQLModel):
    group_name: str
    description: Optional[str] = None
    permissions: List[PermissionCode] = []
    add_creator_to_group: bool = False
