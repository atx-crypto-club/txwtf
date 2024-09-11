import os

from decouple import config

from sqlalchemy import Engine
from sqlmodel import create_engine, SQLModel, Session


def get_engine(db_url: str = None, echo: bool = False):
    if db_url is None:
        db_url = config("TXWTF_API_DATABASE_URL", default="sqlite://")
    return create_engine(db_url, echo=echo)


def init_db(engine: Engine):
    SQLModel.metadata.create_all(engine)


def get_session(engine):
    with Session(engine) as session:
        yield session
