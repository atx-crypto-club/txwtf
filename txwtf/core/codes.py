from enum import IntEnum


SystemLogEventCode = IntEnum(
    "SystemLogEventCode",
    [
        "UserLogin",
        "UserCreate",
        "UserLogout",
        "SettingChange"
    ]
)

UserChangeEventCode = IntEnum(
    "UserChangeEventCode",
    [
        "UserLogin",
        "UserCreate",
        "UserLogout",
        "DeactivateSession"
    ]
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
        "UknownSession",
        "UserNull",
    ],
)