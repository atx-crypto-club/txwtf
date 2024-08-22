import cProfile
import logging
from hashlib import sha256
import pstats
import re
import secrets
import sys
from contextlib import contextmanager
from datetime import datetime
from typing import Tuple, Any, List, Optional

from sqlmodel import Session, select
from sqlalchemy.exc import NoResultFound

from email_validator import validate_email, EmailNotValidError

from werkzeug.security import generate_password_hash, check_password_hash

from txwtf.core.model import (
    GlobalSettings, User, UserChange, SystemLog
)

from txwtf.core.codes import (
    SystemLogEventCode,
    UserChangeEventCode,
    ErrorCode
)
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
    PasswordError,
    RegistrationError,
    LoginError,
    LogoutError,
    SettingsError,
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


def gen_secret():
    return sha256(str(secrets.SystemRandom().getrandbits(128)).encode()).hexdigest()


def remote_addr(request):
    """
    Get the client address through the proxy if it exists.
    """
    return request.headers.get(
        "X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr)
    )


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


def get_setting_record(
        session: Session,
        *args, 
        parent_id: Optional[int] = None,
        create: Optional[bool] = False,
        default: Optional[Any] = None,
        now: Optional[datetime] = None) -> GlobalSettings:

    if now is None:
        now = datetime.utcnow()

    setting = None
    for idx, var in enumerate(args):
        if not valid_identifier(var):
            raise SettingsError(
                ErrorCode.InvalidIdentifier,
                "Invalid indentifier " + var
            )
        val = None
        if idx == len(args) - 1:
            val = default
        setting = (
            session.query(GlobalSettings)
            .filter(GlobalSettings.var == var, GlobalSettings.parent_id == parent_id)
            .first()
        )
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
            session.commit()
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


def has_setting(
        session: Session,
        *args,
        parent_id: Optional[int] = None) -> bool:
    """
    Returns a whether args with parent id points to an
    existing record.
    """
    for var in args:
        setting = (
            session.query(GlobalSettings)
            .filter(GlobalSettings.var == var, GlobalSettings.parent_id == parent_id)
            .first()
        )
        if setting is None:
            return False
        parent_id = setting.id
    return True


def list_setting(
        session: Session,
        *args, 
        parent_id: Optional[int] = None) -> List[str]:
    """
    Returns a list of child vars for this setting.
    """
    retval = []
    setting = get_setting_record(
        session,
        *args, parent_id=parent_id)
    if setting is None:
        return retval
    children = (
        session.query(GlobalSettings)
        .filter(GlobalSettings.parent_id == setting.id)
        .all()
    )
    for child in children:
        retval.append(child.var)
    return retval


def set_setting(
        session: Session,
        *args, 
        parent_id: Optional[int] = None,
        now: Optional[datetime] = None,
        do_commit: Optional[bool] = True) -> GlobalSettings:
    """
    Sets a setting to the global settings table.
    """
    var = args[:-1]
    value = str(args[-1])
    setting = get_setting_record(
        session,
        *var, parent_id=parent_id, create=True, default=value, now=now
    )
    if setting is not None and setting.val != value:
        setting.val = value
        setting.modified_time = datetime.utcnow()
        if do_commit:
            session.commit()
        return setting
    return setting


def get_setting(
        session: Session,
        *args,
        default: Optional[Any] = None,
        parent_id: Optional[int] = None) -> str:
    create = False
    if default is not None:
        create = True
    setting = get_setting_record(
        session,
        *args, parent_id=parent_id, default=default, create=create
    )
    if setting is not None:
        return setting.val
    return None


def get_site_logo(
        session: Session,
        default: Optional[Any] = SITE_LOGO):
    return get_setting(
        session, "site_logo", default=default)


def get_default_avatar(
        session: Session,
        default: Optional[Any] = AVATAR):
    return get_setting(
        session, "default_avatar", default=default)


def get_default_card_image(
        session: Session,
        default: Optional[Any] = CARD_IMAGE):
    return get_setting(
        session, "default_card", default=default)


def get_default_header_image(
        session: Session,
        default: Optional[Any] = HEADER_IMAGE):
    return get_setting(
        session, "default_header", default=default)


def get_password_special_symbols(session: Session,
        default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS):
    return get_setting(
        session, "passwd_special_symbols", default=default)


def get_password_min_length(
        session: Session,
        default: Optional[Any] = PASSWORD_MINIMUM_LENGTH):
    return int(get_setting(
        session, "passwd_minimum_length", default=default))


def get_password_max_length(
        session: Session,
        default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH):
    return int(get_setting(
        session, "passwd_maximum_length", default=default))


def get_password_special_symbols_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS_ENABLED):
    return int(get_setting(
        session, "passwd_special_sym_enabled", default=default))


def get_password_min_length_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_MINIMUM_LENGTH_ENABLED):
    return int(get_setting(
        session, "passwd_minimum_len_enabled", default=default))


def get_password_max_length_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH_ENABLED):
    return int(get_setting(
        session, "passwd_maximum_len_enabled", default=default))


def get_password_digit_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_DIGIT_ENABLED):
    return int(get_setting(
        session, "passwd_digit_enabled", default=default))


def get_password_upper_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_UPPER_ENABLED):
    return int(get_setting(
        session, "passwd_upper_enabled", default=default))


def get_password_lower_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_LOWER_ENABLED):
    return int(get_setting(
        session, "passwd_lower_enabled", default=default))


def password_check(session: Session, passwd: str):
    """
    Check password for validity and throw an error if invalid
    based on global flags and settings.
    """
    password_min_length_enabled = get_password_min_length_enabled(session)
    password_max_length_enabled = get_password_max_length_enabled(session)
    password_digit_enabled = get_password_digit_enabled(session)
    password_upper_enabled = get_password_upper_enabled(session)
    password_lower_enabled = get_password_lower_enabled(session)
    password_special_symbols_enabled = get_password_special_symbols_enabled(session)

    special_sym = get_password_special_symbols(session)
    min_length = get_password_min_length(session)
    max_length = get_password_max_length(session)

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

    # Check if password contains at least one digit, uppercase letter, lowercase letter, and special symbol
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
            ErrorCode.PasswordMissingDigit, "Password should have at least one numeral"
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
            "Password should have at least one of the symbols {}".format(special_sym),
        )


def get_email_validate_deliverability_enabled(
        session: Session,
        default: Optional[Any] = EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
):
    return int(get_setting(
        session, "email_validate_deliv_enabled", default=default))


def register_user(
        session: Session,
        username: str,
        password: str, 
        verify_password: str,
        name: str,
        email: str,
        request: Any,
        cur_time: Optional[datetime] = None
) -> User:
    """
    Perform user registration.
    """
    if password != verify_password:
        raise RegistrationError(ErrorCode.PasswordMismatch, "Password mismatch!")

    # make sure the password passes system checks
    password_check(session, password)

    # if this returns a user, then the email already exists in database
    statement = select(User).where(User.email == email)
    results = session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    # if a user is found by email, throw an error
    if user is not None:
        raise RegistrationError(ErrorCode.EmailExists, "Email address already exists")

    # if this returns a user, then the username already exists in database
    statement = select(User).where(User.username == username)
    results = session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    if user is not None:
        raise RegistrationError(ErrorCode.UsernameExists, "Username already exists")

    # check email validity
    check_deliverability = get_email_validate_deliverability_enabled(session)
    try:
        emailinfo = validate_email(email, check_deliverability=check_deliverability)
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
        avatar_url=get_default_avatar(session),
        card_image_url=get_default_card_image(session),
        header_image_url=get_default_header_image(session),
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
    session.commit()  # commit now to create new user id

    new_change = UserChange(
        user_id=new_user.id,
        change_code=UserChangeEventCode.UserCreate,
        change_time=now,
        change_desc="creating new user {} [{}]".format(new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    new_log = SystemLog(
        event_code=SystemLogEventCode.UserCreate,
        event_time=now,
        event_desc="creating new user {} [{}]".format(new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_log)
    session.commit()

    return new_user


def execute_login(
        session: Session,
        username: str,
        password: str,
        request: Any, 
        cur_time: Optional[datetime] = None
) -> Tuple[User, str]:
    """
    Record a login and execute a provided login function if the supplied
    credentials are correct. Returns a tuple of the User record and
    a signed token.
    """
    statement = select(User).where(User.username == username)
    results = session.exec(statement)
    user = None
    try:
        user = results.one()
    except NoResultFound:
        pass

    # check if the user exists
    if user is None:
        raise LoginError(ErrorCode.UserDoesNotExist, "Access denied!")

    # take the user-supplied password, hash it, and compare it
    # to the hashed password in the database
    if not check_password_hash(user.password, password):
        raise LoginError(ErrorCode.UserPasswordIncorrect, "Access denied!")

    #if login_function is not None:
    #    login_function(user, remember=remember)
    # TODO: generate jwt token and create session record then return the signed token
    # at the end 

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
        change_code=UserChangeEventCode.UserLogin,
        change_time=now,
        change_desc="logging in from {}".format(remote_addr(request)),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    session.commit()

    return user, None

# TODO: invalidate a token without logging all out at once

def execute_logout(
        session: Session,
        request: Any,
        current_user: Optional[User] = None, 
        cur_time: Optional[datetime] = None):
    """
    Record a logout and execute logout by invalidating all a
    users tokens.
    """
    if current_user is None:
        raise LogoutError(ErrorCode.UserNull, "Null user")

    if cur_time is None:
        cur_time = datetime.utcnow()

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
        change_code=UserChangeEventCode.UserLogout,
        change_time=cur_time,
        change_desc="logging out from {}".format(remote_addr(request)),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint,
    )
    session.add(new_change)
    session.commit()

    # TODO: invalidate all current active tokens.
