from datetime import datetime, timedelta
from typing import Optional
import uuid

# from pydantic import BaseModel, Field, EmailStr
from pydantic import EmailStr

from sqlmodel import SQLModel, Column, Field
from sqlalchemy import DateTime, String, func


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, sa_type=String(256), max_length=256)
    email: str = Field(unique=True, sa_type=String(256), max_length=256)
    password: str = Field(sa_type=String(1024), max_length=1024)
    name: str = Field(sa_type=String(1024), max_length=1024)
    avatar_url: Optional[str] = Field(default=None, sa_type=String(1024), max_length=1024)
    header_image_url: Optional[str] = Field(default=None, sa_type=String(1024), max_length=1024)
    header_text: Optional[str] = Field(default=None, sa_type=String(1024), max_length=1024)
    card_image_url: Optional[str] = Field(default=None, sa_type=String(1024), max_length=1024)
    alternate_email: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    email_verified: Optional[bool] = False
    alternate_email_verified: Optional[bool] = False
    description: Optional[str] = Field(default=None, sa_type=String(10240), max_length=10240)
    created_time: Optional[datetime] = Field(default_factory=datetime.utcnow)
    modified_time: Optional[datetime] = Field(
        sa_column=Column(DateTime(), onupdate=func.now())
    )
    accessed_time: Optional[datetime] = Field(default_factory=datetime.utcnow)
    is_admin: Optional[bool] = False
    last_login: Optional[datetime] = None
    last_login_addr: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    view_count: Optional[int] = 0
    post_view_count: Optional[int] = 0
    post_count: Optional[int] = 0
    enabled: bool = True


class GlobalSettings(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    var: str
    val: Optional[str] = None
    parent_id: Optional[int] = None
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")  # track user that created this setting
    created_time: datetime = Field(default_factory=datetime.utcnow)
    modified_time: Optional[datetime] = Field(
        sa_column=Column(DateTime(), onupdate=func.now())
    )
    accessed_time: datetime = Field(default_factory=datetime.utcnow)


class UserChange(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    change_code: int
    change_time: Optional[datetime] = Field(default_factory=datetime.utcnow)
    change_desc: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    referrer: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    user_agent: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    remote_addr: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    endpoint: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)


class SystemLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    event_code: int
    event_time: Optional[datetime] = Field(default_factory=datetime.utcnow)
    event_desc: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    referrer: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    user_agent: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    remote_addr: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    endpoint: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)


class AuthorizedSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()), sa_type=String(48), max_length=48, unique=True, index=True)
    user_id: int = Field(foreign_key="user.id")
    hashed_secret: str = Field(sa_type=String(32), max_length=32)
    active: Optional[bool] = True
    created_time: Optional[datetime] = Field(default_factory=datetime.utcnow)
    expires_time: Optional[datetime] = Field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1))
    referrer: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    user_agent: Optional[str] = Field(default=None, sa_type=String(512), max_length=512)
    remote_addr: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
    endpoint: Optional[str] = Field(default=None, sa_type=String(256), max_length=256)
