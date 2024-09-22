from enum import IntEnum


SystemLogEventCode = IntEnum(
    "SystemLogEventCode",
    [
        "UserLogin",
        "UserCreate",
        "UserLogout",
        "SettingChange",
        "DeactivateSession",
        "LaunchSession",
        "GroupCreate",
        "GroupDelete",
        "GroupAddUser",
        "GroupRemoveUser"
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
        "InvalidGroup",
        "GroupMissingUser",
    ],
)


PermissionCode = IntEnum(
    "PermissionCode",
    [
        "get_setting_record",
        "has_setting",
        "list_setting",
        "set_setting",
        "get_user",
        "get_groups",
        "get_group",
        "has_group",
        "create_group",
        "remove_group",
        "is_user_in_group",
        "add_user_to_group",
        "remove_user_from_group",
        "get_users_groups",
    ],
)