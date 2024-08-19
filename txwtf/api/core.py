from datetime import datetime
from enum import IntEnum
from typing import Any, List, Optional

from sqlmodel import Session

from txwtf.api.model import GlobalSettings


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
