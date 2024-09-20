import cProfile
import logging
from hashlib import sha256
import pstats
import re
import secrets
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
import time
from typing import Tuple, Any, List, Optional, Dict
import uuid

import jwt
from jwt.exceptions import InvalidSignatureError

from pydantic import EmailStr

from sqlmodel import Session, select
from sqlmodel.ext.asyncio.session import AsyncSession

from sqlalchemy.exc import NoResultFound

from email_validator import validate_email, EmailNotValidError

from asyncer import asyncify

from werkzeug.security import generate_password_hash, check_password_hash

from txwtf.core.model import (
    AuthorizedSession,
    GlobalSettings,
    Group,
    GroupAssociation,
    User,
    UserChange,
    SystemLog,
)
from txwtf.core.codes import SystemLogEventCode, UserChangeEventCode, ErrorCode
from txwtf.core.defaults import (
    SITE_LOGO,
    AVATAR,
    CARD_IMAGE,
    HEADER_IMAGE,
    PASSWORD_SPECIAL_SYMBOLS,
    PASSWORD_MINIMUM_LENGTH,
    PASSWORD_MAXIMUM_LENGTH,
    PASSWORD_SPECIAL_SYMBOLS_ENABLED,
    PASSWORD_MINIMUM_LENGTH_ENABLED,
    PASSWORD_MAXIMUM_LENGTH_ENABLED,
    PASSWORD_DIGIT_ENABLED,
    PASSWORD_UPPER_ENABLED,
    PASSWORD_LOWER_ENABLED,
    EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
)
from txwtf.core.errors import (
    AuthorizedSessionError,
    PasswordError,
    RegistrationError,
    LoginError,
    LogoutError,
    SettingsError,
    UserError,
    GroupError,
    TXWTFError,
)


logger = logging.getLogger(__name__)
LOG_FORMAT = "%(asctime)s %(levelname)-8.8s [%(name)s:%(lineno)s] %(message)s"


def setup_logging(log="-", log_level=logging.DEBUG, log_format=LOG_FORMAT):
    """
    Initialize logging for the app.
    """
    root = logging.getLogger()
    formatter = logging.Formatter(log_format)

    if log == "-":
        sh = logging.StreamHandler()
        sh.setLevel(log_level)
        sh.setFormatter(formatter)
        root.addHandler(sh)
    elif log:
        fh = logging.FileHandler(filename=log, mode="w")
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        root.addHandler(fh)

    root.setLevel(logging.DEBUG)


def hash(val: str) -> str:
    return sha256(val.encode()).hexdigest()


def gen_secret() -> str:
    return hash(str(secrets.SystemRandom().getrandbits(128)))


def remote_addr(request):
    """
    Get the client address through the proxy if it exists.
    """
    return request.headers.get(
        "X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr)
    )


def request_compat(request, user_agent):
    """
    Add fields to request to make the object compatible with txwtf routines
    that read request data and expect the attributes provided by flask.
    """
    request.remote_addr = request.client.host
    request.endpoint = str(request.url)
    request.user_agent = user_agent
    request.referrer = request.headers.get("referer")
    return request


@contextmanager
def cli_context(obj):
    """
    Context manager for CLI options.
    """
    if obj.profiling:
        logger.info("enabling profiling")
        pr = cProfile.Profile()
        pr.enable()

    yield obj

    if obj.profiling:
        pr.disable()
        prof = pstats.Stats(pr, stream=sys.stdout)
        ps = prof.sort_stats("cumulative")
        ps.print_stats(300)


def stub():
    return True


def valid_identifier(value):
    """
    Return whether the value is a valid identifier string for
    usernames, hashtags and other objects in the system.
    """
    # C identifier regex
    # http://bit.ly/1MExKtn
    c_ident_re = r"^[_a-zA-Z][_a-zA-Z0-9]{0,30}$"
    return re.match(c_ident_re, value) is not None


async def get_setting_record(
    session: AsyncSession,
    *args,
    parent_id: Optional[int] = None,
    create: Optional[bool] = False,
    default: Optional[Any] = None,
    now: Optional[datetime] = None
) -> GlobalSettings:

    if now is None:
        now = datetime.utcnow()

    setting = None
    for idx, var in enumerate(args):
        if not valid_identifier(var):
            raise SettingsError(
                ErrorCode.InvalidIdentifier, "Invalid indentifier " + var
            )
        val = None
        if idx == len(args) - 1:
            val = default

        statement = select(GlobalSettings).where(
            GlobalSettings.var == var,
            GlobalSettings.parent_id == parent_id
        )
        results = await session.exec(statement)
        setting = None
        try:
            setting = results.one()
        except NoResultFound:
            pass

        if setting is not None:
            setting.accessed_time = now
        if setting is None and create:
            setting = GlobalSettings(
                var=var,
                val=val,
                parent_id=parent_id,
                created_time=now,
                modified_time=now,
                accessed_time=now,
            )
            session.add(setting)
        if create or setting is not None:
            await session.commit()
        if setting is None and not create:
            parent_id_str = ""
            if parent_id is not None:
                parent_id_str = "{}:".format(parent_id)
            raise SettingsError(
                ErrorCode.SettingDoesntExist,
                "{}{}".format(parent_id_str, ".".join(args[: idx + 1])),
            )
        parent_id = setting.id

    return setting


async def has_setting(
    session: AsyncSession, *args,
    parent_id: Optional[int] = None
) -> bool:
    """
    Returns a whether args with parent id points to an
    existing record.
    """
    for var in args:
        statement = select(GlobalSettings).where(
            GlobalSettings.var == var,
            GlobalSettings.parent_id == parent_id
        )
        results = await session.exec(statement)
        setting = None
        try:
            setting = results.one()
        except NoResultFound:
            pass

        if setting is None:
            return False
        parent_id = setting.id
    return True


async def list_setting(
    session: AsyncSession,
    *args,
    parent_id: Optional[int] = None
) -> List[str]:
    """
    Returns a list of child vars for this setting.
    """
    retval = []
    setting = await get_setting_record(
        session, *args, parent_id=parent_id
    )
    if setting is None:
        return retval

    statement = select(GlobalSettings).where(
        GlobalSettings.parent_id == setting.id
    )
    results = await session.exec(statement)
    children = None
    try:
        children = results.all()
    except NoResultFound:
        pass

    if children is not None:
        for child in children:
            retval.append(child.var)
    return retval


async def set_setting(
    session: AsyncSession,
    *args,
    parent_id: Optional[int] = None,
    now: Optional[datetime] = None,
    do_commit: Optional[bool] = True
) -> GlobalSettings:
    """
    Sets a setting to the global settings table.
    """
    var = args[:-1]
    value = str(args[-1])
    setting = await get_setting_record(
        session,
        *var,
        parent_id=parent_id,
        create=True,
        default=value,
        now=now
    )
    if setting is not None and setting.val != value:
        setting.val = value
        setting.modified_time = datetime.utcnow()
        if do_commit:
            await session.commit()
        return setting
    return setting


async def get_setting(
    session: AsyncSession,
    *args,
    default: Optional[Any] = None,
    parent_id: Optional[int] = None
) -> str:
    create = False
    if default is not None:
        create = True
    setting = await get_setting_record(
        session,
        *args,
        parent_id=parent_id,
        default=default,
        create=create
    )
    if setting is not None:
        return setting.val
    return None


async def get_site_logo(
    session: AsyncSession, 
    default: Optional[Any] = SITE_LOGO
):
    return await get_setting(
        session,
        "site_logo",
        default=default
    )


async def get_default_avatar(
    session: AsyncSession,
    default: Optional[Any] = AVATAR
):
    return await get_setting(
        session,
        "default_avatar",
        default=default
    )


async def get_default_card_image(
    session: AsyncSession,
    default: Optional[Any] = CARD_IMAGE
):
    return await get_setting(
        session,
        "default_card",
        default=default
    )


async def get_default_header_image(
    session: AsyncSession,
    default: Optional[Any] = HEADER_IMAGE
):
    return await get_setting(
        session,
        "default_header",
        default=default
    )


async def get_password_special_symbols(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS
):
    return await get_setting(
        session,
        "passwd_special_symbols",
        default=default)


async def get_password_min_length(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_MINIMUM_LENGTH
):
    return int(await get_setting(
        session,
        "passwd_minimum_length",
        default=default
    ))


async def get_password_max_length(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH
):
    return int(await get_setting(
        session,
        "passwd_maximum_length",
        default=default
    ))


async def get_password_special_symbols_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_special_sym_enabled",
        default=default
    ))


async def get_password_min_length_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_MINIMUM_LENGTH_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_minimum_len_enabled",
        default=default
    ))


async def get_password_max_length_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_maximum_len_enabled",
        default=default
    ))


async def get_password_digit_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_DIGIT_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_digit_enabled",
        default=default
    ))


async def get_password_upper_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_UPPER_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_upper_enabled",
        default=default
    ))


async def get_password_lower_enabled(
    session: AsyncSession,
    default: Optional[Any] = PASSWORD_LOWER_ENABLED
):
    return int(await get_setting(
        session,
        "passwd_lower_enabled",
        default=default
    ))


async def password_check(session: AsyncSession, passwd: str):
    """
    Check password for validity and throw an error if invalid
    based on global flags and settings.
    """
    password_min_length_enabled = await get_password_min_length_enabled(session)
    password_max_length_enabled = await get_password_max_length_enabled(session)
    password_digit_enabled = await get_password_digit_enabled(session)
    password_upper_enabled = await get_password_upper_enabled(session)
    password_lower_enabled = await get_password_lower_enabled(session)
    password_special_symbols_enabled = await get_password_special_symbols_enabled(
        session
    )

    special_sym = await get_password_special_symbols(session)
    min_length = await get_password_min_length(session)
    max_length = await get_password_max_length(session)

    if len(special_sym) == 0:
        password_special_symbols_enabled = False

    if password_min_length_enabled and len(passwd) < min_length:
        raise PasswordError(
            ErrorCode.PasswordTooShort,
            "length should be at least {}".format(min_length),
        )
    if password_max_length_enabled and len(passwd) > max_length:
        raise PasswordError(
            ErrorCode.PasswordTooLong,
            "length should be not be greater than {}".format(max_length),
        )

    # Check if password contains at least one digit, uppercase letter,
    # lowercase letter, and special symbol.
    has_digit = False
    has_upper = False
    has_lower = False
    has_sym = False
    for char in passwd:
        if ord(char) >= 48 and ord(char) <= 57:
            has_digit = True
        elif ord(char) >= 65 and ord(char) <= 90:
            has_upper = True
        elif ord(char) >= 97 and ord(char) <= 122:
            has_lower = True
        elif char in special_sym:
            has_sym = True

    if password_digit_enabled and not has_digit:
        raise PasswordError(
            ErrorCode.PasswordMissingDigit,
            "Password should have at least one numeral"
        )
    if password_upper_enabled and not has_upper:
        raise PasswordError(
            ErrorCode.PasswordMissingUpper,
            "Password should have at least one uppercase letter",
        )
    if password_lower_enabled and not has_lower:
        raise PasswordError(
            ErrorCode.PasswordMissingLower,
            "Password should have at least one lowercase letter",
        )
    if password_special_symbols_enabled and not has_sym:
        raise PasswordError(
            ErrorCode.PasswordMissingSymbol,
            "Password should have at least one of the symbols {}".format(
                special_sym
            ),
        )


def sign_jwt(
    jwt_secret: str,
    jwt_algorithm: str,
    user_id: int,
    expires: Optional[timedelta] = timedelta(hours=2),
    cur_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    if cur_time is None:
        cur_time = datetime.utcnow()
    expire_time = cur_time + expires
    payload = {
        "user_id": user_id,
        "expires": time.mktime(expire_time.timetuple()),
        "uuid": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)
    payload.update({"token": token})
    return payload


def decode_jwt(
    jwt_secret: str,
    jwt_algorithm: str,
    token: str
) -> Dict[str, str]:
    try:
        ret = jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
    except InvalidSignatureError as e:
        raise AuthorizedSessionError(
            ErrorCode.InvalidTokenSignature, "Invalid token signature"
        )

    return ret


async def authorized_session_launch(
    session: AsyncSession,
    user_id: int,
    jwt_secret: str,
    jwt_algorithm: str,
    request: Any,
    expire_delta: Optional[timedelta] = None,
    cur_time: Optional[datetime] = None,
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
    results = await session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.InvalidUser, "Invalid user id {}".format(user_id)
        )

    if not user.enabled:
        raise AuthorizedSessionError(
            ErrorCode.DisabledUser, "Disabled user {}".format(user_id)
        )

    session_payload = sign_jwt(
        jwt_secret, jwt_algorithm, user.id, expire_delta, cur_time
    )
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
        event_code=UserChangeEventCode.LaunchSession,
        event_time=cur_time,
        event_desc="launching session {}".format(session_uuid),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    await session.commit()

    return session_payload


async def authorized_sessions(
    session: AsyncSession,
    user_id: Optional[int] = None,
    verified_only: Optional[bool] = False,
    jwt_secret: Optional[str] = None,
) -> List[AuthorizedSession]:
    """
    Returns all authorized sessions that match the user_id.
    """
    statement = select(AuthorizedSession)
    if user_id is not None:
        statement = statement.where(AuthorizedSession.user_id == user_id)
    statement = statement.order_by(AuthorizedSession.created_time.desc())
    result = await session.exec(statement)
    sessions = result.all()
    if not verified_only:
        return sessions
    if jwt_secret is None:
        raise AuthorizedSessionError(
            ErrorCode.InvalidSecret,
            "Null secret when trying to return verified authorized sessions",
        )
    verified_sessions = []
    for auth_session in sessions:
        try:
            await authorized_session_verify(session, auth_session.uuid, jwt_secret)
            verified_sessions.append(auth_session)
        except TXWTFError as e:
            pass
    return verified_sessions


async def authorized_session_verify(
    session: AsyncSession, session_uuid: str, jwt_secret: str
):
    """
    Raises an exception if there is a problem with the
    session or if it has been deactivated.
    """
    statement = select(AuthorizedSession).where(
        AuthorizedSession.uuid == session_uuid
    )
    results = await session.exec(statement)

    # get the session
    auth_sess = None
    try:
        auth_sess = results.one()
    except NoResultFound:
        raise AuthorizedSessionError(
            ErrorCode.UknownSession,
            "Cannot find session {}".format(session_uuid)
        )

    # check if this session matches the secret
    if hash(jwt_secret) != auth_sess.hashed_secret:
        raise AuthorizedSessionError(
            ErrorCode.InvalidSession,
            "Secret mismatch"
        )

    # check if it is expired
    if auth_sess.expires_time <= datetime.utcnow():
        raise AuthorizedSessionError(
            ErrorCode.ExpiredSession,
            "Session {} is expired since {}".format(
                session_uuid, auth_sess.expires_time
            ),
        )

    # get the user and check if the account is still enabled
    statement = select(User).where(User.id == auth_sess.user_id)
    results = await session.exec(statement)
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
            "Disabled user {}({})".format(user.username, user.id),
        )

    # check if the session was deactivated.
    if not auth_sess.active:
        raise AuthorizedSessionError(
            ErrorCode.DeactivatedSession,
            "Deactivated session {}".format(session_uuid)
        )


async def authorized_session_deactivate(
    session: AsyncSession,
    session_uuid: str,
    request: Any,
    cur_time: Optional[datetime] = None,
):
    """
    Set the session as deactivated. Future commands with the session token
    should have an authorization error.
    """
    statement = select(AuthorizedSession).where(
        AuthorizedSession.uuid == session_uuid
    )
    results = await session.exec(statement)
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
        event_code=UserChangeEventCode.DeactivateSession,
        event_time=cur_time,
        event_desc="deactivating session {}".format(session_uuid),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    await session.commit()


async def get_email_validate_deliverability_enabled(
    session: AsyncSession,
    default: Optional[Any] = EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
):
    return int(await get_setting(
        session,
        "email_validate_deliv_enabled",
        default=default
    ))


async def register_user(
    session: AsyncSession,
    username: str,
    password: str,
    verify_password: str,
    name: str,
    email: EmailStr,
    request: Any,
    cur_time: Optional[datetime] = None,
) -> User:
    """
    Perform user registration.
    """
    if password != verify_password:
        raise RegistrationError(
            ErrorCode.PasswordMismatch,
            "Password mismatch!"
        )

    # make sure the password passes system checks
    await password_check(session, password)

    # if this returns a user, then the email already exists in database
    statement = select(User).where(User.email == email)
    results = await session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    # if a user is found by email, throw an error
    if user is not None:
        raise RegistrationError(
            ErrorCode.EmailExists,
            "Email address already exists"
        )

    # if the username is an invalid identifier, bail
    if not valid_identifier(username):
        raise RegistrationError(
            ErrorCode.InvalidIdentifier,
            "Invalid indentifier " + username
        )

    # if this returns a user, then the username already exists in database
    statement = select(User).where(User.username == username)
    results = await session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    if user is not None:
        raise RegistrationError(
            ErrorCode.UsernameExists,
            "Username already exists")

    # check email validity
    check_deliverability = (
        await get_email_validate_deliverability_enabled(session)
    )
    try:
        emailinfo = await asyncify(validate_email)(
            email,
            check_deliverability=check_deliverability
        )
        email = emailinfo.normalized
    except EmailNotValidError as e:
        raise RegistrationError(ErrorCode.InvalidEmail, str(e))

    if cur_time is None:
        now = datetime.utcnow()
    else:
        now = cur_time

    # create a new user with the form data. Hash the password so the
    # plaintext version isn't saved.
    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password),
        created_time=now,
        modified_time=now,
        avatar_url=await get_default_avatar(session),
        card_image_url=await get_default_card_image(session),
        header_image_url=await get_default_header_image(session),
        header_text=name,
        description="{} is on the scene".format(name),
        email_verified=False,
        is_admin=False,
        last_login=None,
        last_login_addr=None,
        view_count=0,
        post_view_count=0,
        username=username,
        post_count=0,
    )

    # add the new user to the database
    session.add(new_user)
    await session.commit()  # commit now to create new user id

    new_change = UserChange(
        user_id=new_user.id,
        event_code=UserChangeEventCode.UserCreate,
        event_time=now,
        event_desc="creating new user {} [{}]".format(
            new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=str(request.endpoint),
    )
    session.add(new_change)
    new_log = SystemLog(
        event_code=SystemLogEventCode.UserCreate,
        event_time=now,
        event_desc="creating new user {} [{}]".format(
            new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=str(request.endpoint),
    )
    session.add(new_log)
    await session.commit()

    await session.refresh(new_user)

    return new_user


async def execute_login(
    session: AsyncSession,
    username: str,
    password: str,
    jwt_secret: str,
    jwt_algorithm: str,
    request: Any,
    expire_delta: timedelta = timedelta(hours=1),
    cur_time: Optional[datetime] = None,
) -> Tuple[User, Dict[str, Any]]:
    """
    Record a login and execute a provided login function if the supplied
    credentials are correct. Returns a tuple of the User record and
    a signed token.
    """
    statement = select(User).where(User.username == username)
    results = await session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    # check if the user exists
    if user is None:
        raise LoginError(
            ErrorCode.UserDoesNotExist,
            "Access denied!"
        )

    # take the user-supplied password, hash it, and compare it
    # to the hashed password in the database
    if not check_password_hash(user.password, password):
        raise LoginError(
            ErrorCode.UserPasswordIncorrect,
            "Access denied!"
        )

    token_payload = await authorized_session_launch(
        session,
        user.id,
        jwt_secret,
        jwt_algorithm,
        request,
        expire_delta,
        cur_time
    )

    if cur_time is None:
        cur_time = datetime.utcnow()

    now = cur_time
    user.last_login = now
    user.last_login_addr = remote_addr(request)
    new_log = SystemLog(
        event_code=SystemLogEventCode.UserLogin,
        event_time=now,
        event_desc="user {} [{}] logged in".format(user.username, user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_log)
    new_change = UserChange(
        user_id=user.id,
        event_code=UserChangeEventCode.UserLogin,
        event_time=now,
        event_desc="logging in from {}".format(remote_addr(request)),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    await session.commit()

    await session.refresh(user)

    return user, token_payload


async def execute_logout(
    session: AsyncSession,
    session_uuid: str,
    jwt_secret: str,
    request: Any,
    current_user: User,
    cur_time: Optional[datetime] = None,
):
    """
    Record a logout and execute logout by invalidating the session
    by its uuid.
    """
    if cur_time is None:
        cur_time = datetime.utcnow()

    await authorized_session_verify(session, session_uuid, jwt_secret)

    new_log = SystemLog(
        event_code=SystemLogEventCode.UserLogout,
        event_time=cur_time,
        event_desc="user {} [{}] logging out".format(
            current_user.username, current_user.id
        ),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_log)
    new_change = UserChange(
        user_id=current_user.id,
        event_code=UserChangeEventCode.UserLogout,
        event_time=cur_time,
        event_desc="logging out from {}".format(remote_addr(request)),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    await session.commit()

    await authorized_session_deactivate(
        session,
        session_uuid,
        request,
        cur_time
    )


async def get_user(session: AsyncSession, user_id: int) -> User:
    statement = select(User).where(User.id == user_id)
    results = await session.exec(statement)
    try:
        return results.one()
    except NoResultFound:
        raise UserError(
            ErrorCode.InvalidUser,
            "Invalid user id {}".format(user_id)
        )


async def get_groups(session: AsyncSession) -> List[Group]:
    statement = select(Group)
    results = await session.exec(statement)
    return results.all()


async def has_group(session: AsyncSession, name: str) -> bool:
    statement = select(Group).where(Group.name == name)
    results = await session.exec(statement)
    group = None
    try:
        group = results.one()
    except NoResultFound:
        pass
    return group is not None


async def create_group(session: AsyncSession, name: str) -> Group:
    if await has_group(session, name):
        raise GroupError(
            ErrorCode.GroupExists,
            "Group {} already exists".format(group)
        )

    group = Group(name=name)
    session.add(group)
    await session.commit()
    await session.refresh(group)
    return group


async def is_user_in_group(
    session: AsyncSession,
    group_id: int,
    user_id: int
) -> Group:
    statement = select(GroupAssociation).where(
        GroupAssociation.group_id == group_id
        ).where(
            GroupAssociation.user_id == user_id
        )
    results = await session.exec(statement)
    ga = None
    try:
        ga = results.one()
    except NoResultFound:
        pass
    return ga is not None


async def add_user_to_group(
    session: AsyncSession,
    group_id: int,
    user_id: int
) -> GroupAssociation:
    if await is_user_in_group(session, group_id, user_id):
        raise GroupError(
            ErrorCode.GroupHasUser,
            "Group {} already has user {}".format(group_id, user_id)
        )

    ga = GroupAssociation(group_id=group_id, user_id=user_id)
    session.add(ga)
    await session.commit()
    await session.refresh(ga)
    return ga
