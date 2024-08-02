from enum import IntEnum


SystemLogEventCode = IntEnum(
    "SystemLogEventCode", ["UserLogin", "UserCreate", "UserLogout", "SettingChange"]
)

UserChangeEventCode = IntEnum(
    "UserChangeEventCode", ["UserLogin", "UserCreate", "UserLogout"]
)

ErrorCode = IntEnum(
    "ErrorCode",
    [
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
