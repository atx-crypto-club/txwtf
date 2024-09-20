from enum import IntEnum


SystemLogEventCode = IntEnum(
    "SystemLogEventCode",
    [
        "UserLogin",
        "UserCreate",
        "UserLogout",
        "SettingChange",
        "DeactivateSession",
        "LaunchSession"
    ],
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
        "InvalidTokenSignature",
        "InvalidSecret",
        "GroupExists",
        "GroupHasUser",
        "InvalidGroup"
    ],
)
