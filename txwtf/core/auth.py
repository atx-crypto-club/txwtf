from datetime import datetime, timedelta
import time
from typing import List, Dict, Any, Optional
import uuid

import jwt
from decouple import config

from sqlmodel import Session, select
from sqlalchemy.exc import NoResultFound

from txwtf.core.codes import ErrorCode, UserChangeEventCode
from txwtf.core import hash, remote_addr
from txwtf.core.model import AuthorizedSession, User, UserChange
from txwtf.core.errors import AuthorizedSessionError


def sign_jwt(
    jwt_secret: str,
    jwt_algorithm: str,
    user_id: int,
    expires: Optional[timedelta] = timedelta(hours=2),
    cur_time: Optional[datetime] = None
) -> Dict[str, Any]:
    if cur_time is None:
        cur_time = datetime.utcnow()
    expire_time = cur_time + expires
    payload = {
        "user_id": user_id,
        "expires": time.mktime(expire_time.timetuple()),
        "uuid": str(uuid.uuid4())
    }
    token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)
    payload.update({"token": token})
    return payload


def decode_jwt(
    jwt_secret: str,
    jwt_algorithm: str,
    token: str
) -> Dict[str, str]:
    return jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
    

def authorized_session_launch(
        session: Session,
        user_id: int,
        jwt_secret: str,
        jwt_algorithm: str,
        request: Any = None,
        expire_delta: Optional[timedelta] = None,
        cur_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Use this to generate an authorized session record
    for the specified user. It returns the token payload
    with the token itself included in the payload dict.
    """
    if expire_delta is None:
        expire_delta = timedelta(hours=1)
    if cur_time is None:
        cur_time = datetime.utcnow()
    expires = cur_time + expire_delta

    statement = select(User).where(User.id == user_id)
    results = session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.InvalidUser,
            "Invalid user id {}".format(user_id)
        )
    
    if not user.enabled:
        raise AuthorizedSessionError(
            ErrorCode.DisabledUser,
            "Disabled user {}".format(user_id)
        )

    session_payload = sign_jwt(
        jwt_secret, jwt_algorithm, user.id, expire_delta, cur_time)
    session_uuid = session_payload["uuid"]
    new_as = AuthorizedSession(
        user_id=user.id,
        uuid=session_uuid,
        hashed_secret=hash(jwt_secret),
        created_time=cur_time,
        expires_time=expires,
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_as)

    new_change = UserChange(
        user_id=user.id,
        change_code=UserChangeEventCode.LaunchSession,
        change_time=cur_time,
        change_desc="launching session {}".format(session_uuid),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    session.commit()

    return session_payload


def authorized_sessions(
        session: Session,
        user_id: Optional[int] = None,
        active_only: bool = False
) -> List[AuthorizedSession]:
    """
    Returns all authorized sessions that match the user_id.
    """
    statement = select(AuthorizedSession)
    if user_id is not None:
        statement = statement.where(
            AuthorizedSession.user_id == user_id)
    if active_only:
        statement = statement.where(
            AuthorizedSession.active == True)
    statement = statement.order_by(
        AuthorizedSession.created_time.desc())
    result = session.exec(statement)
    return result.all()


def authorized_session_verify(
        session: Session,
        session_uuid: str,
):
    """
    Raises an exception if there is a problem with the
    session or if it has been deactivated.
    """
    statement = select(AuthorizedSession).where(
        AuthorizedSession.uuid == session_uuid)
    results = session.exec(statement)

    # get the session
    auth_sess = None
    try:
        auth_sess = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.UknownSession,
            "Cannot find session {}".format(session_uuid)
        )
    
    # check if it is expired
    if auth_sess.expires_time <= datetime.utcnow():
        raise AuthorizedSessionError(
            ErrorCode.ExpiredSession,
            "Session {} is expired since {}".format(
                session_uuid, auth_sess.expires_time)
        )
    
    # get the user and check if the account is still enabled
    statement = select(User).where(User.id == auth_sess.user_id)
    results = session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.InvalidUser,
            "Invalid user id {}".format(auth_sess.user_id)
        )
    
    if not user.enabled:
        raise AuthorizedSessionError(
            ErrorCode.DisabledUser,
            "Disabled user {}({})".format(user.username, user.id)
        )

    # check if the session was deactivated.
    if not auth_sess.active:
        raise AuthorizedSessionError(
            ErrorCode.DeactivatedSession,
            "Deactivated session {}".format(session_uuid)
        )


def authorized_session_deactivate(
        session: Session,
        session_uuid: str,
        request: Any = None,
        cur_time: Optional[datetime] = None
):
    """
    Set the session as deactivated. Future commands with the session token
    should have an authorization error.
    """
    statement = select(AuthorizedSession).where(
        AuthorizedSession.uuid == session_uuid)
    results = session.exec(statement)
    auth_sess = None
    try:
        auth_sess = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.UknownSession,
            "Cannot find session {}".format(session_uuid)
        )
    auth_sess.active = False
    session.add(auth_sess)

    if cur_time is None:
        cur_time = datetime.utcnow()

    new_change = UserChange(
        user_id=auth_sess.user_id,
        change_code=UserChangeEventCode.DeactivateSession,
        change_time=cur_time,
        change_desc="deactivating session {}".format(session_uuid),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    session.commit()
