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
        "DeactivateSession",
        "LaunchSession"
    ]
)

ErrorCode = IntEnum(
    "ErrorCode",
    [
        "NoError",
        "GenericError",
        "InvalidIdentifier",
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
        "ExpiredSession",
        "InvalidUser",
        "DisabledUser",
        "DeactivatedSession",
        "InvalidSession",
        "InvalidTokenSignature"
    ],
)