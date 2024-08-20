from datetime import datetime
from enum import IntEnum
from typing import Any, List, Optional

from sqlmodel import Session

from txwtf.api.model import GlobalSettings


SITE_LOGO = "/assets/img/atxcf_logo_small.jpg"
AVATAR = "/assets/img/atxcf_logo_small.jpg"
CARD_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"
HEADER_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"
PASSWORD_SPECIAL_SYMBOLS = "$@#%"
PASSWORD_MINIMUM_LENGTH = 8
PASSWORD_MAXIMUM_LENGTH = 64
PASSWORD_SPECIAL_SYMBOLS_ENABLED = 1
PASSWORD_MINIMUM_LENGTH_ENABLED = 1
PASSWORD_MAXIMUM_LENGTH_ENABLED = 1
PASSWORD_DIGIT_ENABLED = 1
PASSWORD_UPPER_ENABLED = 1
PASSWORD_LOWER_ENABLED = 1
EMAIL_VALIDATE_DELIVERABILITY_ENABLED = 1


SystemLogEventCode = IntEnum(
    "SystemLogEventCode", ["UserLogin", "UserCreate", "UserLogout", "SettingChange"]
)

UserChangeEventCode = IntEnum(
    "UserChangeEventCode", ["UserLogin", "UserCreate", "UserLogout"]
)

ErrorCode = IntEnum(
    "ErrorCode",
    [
        "NoError",
        "GenericError",
        "EmailExists",
        "UsernameExists",
        "InvalidEmail",
        "PasswordMismatch",
        "PasswordTooShort",
        "PasswordTooLong",
        "PasswordMissingDigit",
        "PasswordMissingUpper",
        "PasswordMissingLower",
        "PasswordMissingSymbol",
        "UserDoesNotExist",
        "UserPasswordIncorrect",
        "SettingDoesntExist",
        "UserNull",
    ],
)


class PasswordError(Exception):
    pass


class RegistrationError(Exception):
    pass


class LoginError(Exception):
    pass


class LogoutError(Exception):
    pass


class SettingsError(Exception):
    pass


def get_setting_record(
        session: Session,
        *args, 
        parent_id: Optional[int] = None,
        create: Optional[bool] = False,
        default: Optional[Any] = None,
        now: Optional[datetime] = None) -> GlobalSettings:

    if now is None:
        now = datetime.now()

    setting = None
    for idx, var in enumerate(args):
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
        setting.modified_time = datetime.now()
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


def remote_addr(request):
    """
    Get the client address through the proxy if it exists.
    """
    return request.headers.get(
        "X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr)
    )


def get_password_special_symbols(session: Session,
        default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS):
    return get_setting(
        session, "password_special_symbols", default=default)


def get_password_min_length(
        session: Session,
        default: Optional[Any] = PASSWORD_MINIMUM_LENGTH):
    return int(get_setting(
        session, "password_minimum_length", default=default))


def get_password_max_length(
        session: Session,
        default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH):
    return int(get_setting(
        session, "password_maximum_length", default=default))


def get_password_special_symbols_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_SPECIAL_SYMBOLS_ENABLED):
    return int(get_setting(
        session, "password_special_symbols_enabled", default=default))


def get_password_min_length_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_MINIMUM_LENGTH_ENABLED):
    return int(get_setting(
        session, "password_minimum_length_enabled", default=default))


def get_password_max_length_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_MAXIMUM_LENGTH_ENABLED):
    return int(get_setting(
        session, "password_maximum_length_enabled", default=default))


def get_password_digit_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_DIGIT_ENABLED):
    return int(get_setting(
        session, "password_digit_enabled", default=default))


def get_password_upper_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_UPPER_ENABLED):
    return int(get_setting(
        session, "password_upper_enabled", default=default))


def get_password_lower_enabled(
        session: Session,
        default: Optional[Any] = PASSWORD_LOWER_ENABLED):
    return int(get_setting(
        session, "password_lower_enabled", default=default))


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
        session, "email_validate_deliverability_enabled", default=default))
