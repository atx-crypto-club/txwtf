from datetime import datetime
from enum import IntEnum
import logging

from email_validator import validate_email, EmailNotValidError

from werkzeug.security import generate_password_hash

from . import db
from .models import GlobalSettings, User, UserChange, SystemLog


DEFAULT_SITE_LOGO = "/assets/img/atxcf_logo_small.jpg"
DEFAULT_AVATAR = "/assets/img/atxcf_logo_small.jpg"
DEFAULT_CARD_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"
DEFAULT_HEADER_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"
DEFAULT_PASSWORD_SPECIAL_SYMBOLS = '$@#%'
DEFAULT_PASSWORD_MINIMUM_LENGTH = 8
DEFAULT_PASSWORD_MAXIMUM_LENGTH = 64
DEFAULT_PASSWORD_SPECIAL_SYMBOLS_ENABLED = 1
DEFAULT_PASSWORD_MINIMUM_LENGTH_ENABLED = 1
DEFAULT_PASSWORD_MAXIMUM_LENGTH_ENABLED = 1
DEFAULT_PASSWORD_DIGIT_ENABLED = 1
DEFAULT_PASSWORD_UPPER_ENABLED = 1
DEFAULT_PASSWORD_LOWER_ENABLED = 1
DEFAULT_EMAIL_VALIDATE_DELIVERABILITY_ENABLED = 1


SystemLogEventCode = IntEnum(
    'SystemLogEventCode',
    ['UserLogin', 'UserCreate', 'UserLogout', 'SettingChange'])

UserChangeEventCode = IntEnum(
    'UserChangeEventCode',
    ['UserLogin', 'UserCreate', 'UserLogout'])

ErrorCode = IntEnum(
    'ErrorCode',
    ['EmailExists', 'UsernameExists', 'InvalidEmail', 'PasswordMismatch',
     'PasswordTooShort', 'PasswordTooLong', 'PasswordMissingDigit',
     'PasswordMissingUpper', 'PasswordMissingLower', 'PasswordMissingSymbol'])


class PasswordError(Exception):
    pass

class RegistrationError(Exception):
    pass


def get_setting_record(var_name):
    return db.session.query(GlobalSettings).filter(
        GlobalSettings.var == var_name).first()


def get_setting(var_name, default=None):
    setting = get_setting_record(var_name)
    if setting is not None:
        return setting.val
    
    # If no such setting exists with that var name but a default
    # has been set, then set the setting then return the default.
    if default is not None:
        default = str(default)
        set_setting(var_name, default)
        return default

    return None


def set_setting(var_name, value):
    """
    Sets a setting to the global settings table.
    """
    value = str(value)
    setting = get_setting_record(var_name)
    if setting:
        setting.val = value
        db.session.commit()
        return

    setting = GlobalSettings(
        var=var_name,
        val=value)
    db.session.add(setting)
    db.session.commit()


def get_site_logo(default=DEFAULT_SITE_LOGO):
    return get_setting("site_logo", default)


def get_default_avatar(default=DEFAULT_AVATAR):
    return get_setting("default_avatar", default)


def get_default_card_image(default=DEFAULT_CARD_IMAGE):
    return get_setting("default_card", default)


def get_default_header_image(default=DEFAULT_HEADER_IMAGE):
    return get_setting("default_header", default)


def remote_addr(request):
    """
    Get the client address through the proxy if it exists.
    """
    return request.headers.get(
        'X-Forwarded-For', request.headers.get(
            'X-Real-IP', request.remote_addr))


def get_password_special_symbols(
        default=DEFAULT_PASSWORD_SPECIAL_SYMBOLS):
    return get_setting("password_special_symbols", default)


def get_password_min_length(
        default=DEFAULT_PASSWORD_MINIMUM_LENGTH):
    return int(get_setting("password_minimum_length", default))


def get_password_max_length(
        default=DEFAULT_PASSWORD_MAXIMUM_LENGTH):
    return int(get_setting("password_maximum_length", default))


def get_password_special_symbols_enabled(
        default=DEFAULT_PASSWORD_SPECIAL_SYMBOLS_ENABLED):
    return int(get_setting("password_special_symbols_enabled", default))


def get_password_min_length_enabled(
        default=DEFAULT_PASSWORD_MINIMUM_LENGTH_ENABLED):
    return int(get_setting("password_minimum_length_enabled", default))


def get_password_max_length_enabled(
        default=DEFAULT_PASSWORD_MAXIMUM_LENGTH_ENABLED):
    return int(get_setting("password_maximum_length_enabled", default))


def get_password_digit_enabled(
        default=DEFAULT_PASSWORD_DIGIT_ENABLED):
    return int(get_setting("password_digit_enabled", default))


def get_password_upper_enabled(
        default=DEFAULT_PASSWORD_UPPER_ENABLED):
    return int(get_setting("password_upper_enabled", default))


def get_password_lower_enabled(
        default=DEFAULT_PASSWORD_LOWER_ENABLED):
    return int(get_setting("password_lower_enabled", default))


def password_check(passwd):
    """
    Check password for validity and throw an error if invalid
    based on global flags and settings.
    """
    password_min_length_enabled = get_password_min_length_enabled()
    password_max_length_enabled = get_password_max_length_enabled()
    password_digit_enabled = get_password_digit_enabled()
    password_upper_enabled = get_password_upper_enabled()
    password_lower_enabled = get_password_lower_enabled()
    password_special_symbols_enabled = get_password_special_symbols_enabled()

    special_sym = get_password_special_symbols()
    min_length = get_password_min_length()
    max_length = get_password_max_length()

    if len(special_sym) == 0:
        password_special_symbols_enabled = False

    if password_min_length_enabled and len(passwd) < min_length:
        raise PasswordError(
            ErrorCode.PasswordTooShort,
            'length should be at least {}'.format(min_length))
    if password_max_length_enabled and len(passwd) > max_length:
        raise PasswordError(
            ErrorCode.PasswordTooLong,
            'length should be not be greater than {}'.format(max_length))
 
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
            ErrorCode.PasswordMissingDigit,
            'Password should have at least one numeral')
    if password_upper_enabled and not has_upper:
        raise PasswordError(
            ErrorCode.PasswordMissingUpper,
            'Password should have at least one uppercase letter')
    if password_lower_enabled and not has_lower:
        raise PasswordError(
            ErrorCode.PasswordMissingLower,
            'Password should have at least one lowercase letter')
    if password_special_symbols_enabled and not has_sym:
        raise PasswordError(
            ErrorCode.PasswordMissingSymbol,
            'Password should have at least one of the symbols {}'.format(
                special_sym))


def get_email_validate_deliverability_enabled(
        default=DEFAULT_EMAIL_VALIDATE_DELIVERABILITY_ENABLED):
    return int(
        get_setting(
            "email_validate_deliverability_enabled", default))


def register_user(
        username, password, verify_password, name, email,
        request, cur_time=None):
    """
    Perform user registration.
    """
    if password != verify_password:
        raise RegistrationError(
            ErrorCode.PasswordMismatch,
            "Password mismatch!")

    # make sure the password passes system checks
    password_check(password)

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    # if a user is found by email, throw an error
    if user is not None:
        raise RegistrationError(
            ErrorCode.EmailExists,
            'Email address already exists')
    
    # if this returns a user, then the username already exists in database
    user = User.query.filter_by(username=username).first()

    if user:
        raise RegistrationError(
            ErrorCode.UsernameExists,
            'Username already exists')

    # check email validity
    check_deliverability = get_email_validate_deliverability_enabled()
    try:
        emailinfo = validate_email(
            email, check_deliverability=check_deliverability)
        email = emailinfo.normalized
    except EmailNotValidError as e:
        raise RegistrationError(
            ErrorCode.InvalidEmail, str(e))

    if cur_time is None:
        now = datetime.now()
    else:
        now = cur_time

    # create a new user with the form data. Hash the password so the
    # plaintext version isn't saved.
    new_user = User(
        email=email, name=name,
        password=generate_password_hash(password),
        created_time=now,
        modified_time=now,
        avatar_url=get_default_avatar(),
        card_image_url=get_default_card_image(),
        header_image_url=get_default_header_image(),
        header_text=name,
        description="{} is on the scene".format(name),
        email_verified=False,
        is_admin=False,
        last_login=None,
        last_login_addr=None,
        view_count=0,
        post_view_count=0,
        username=username,
        post_count=0)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()  # commit now to create new user id

    new_change = UserChange(
        user_id=new_user.id,
        change_code=UserChangeEventCode.UserCreate,
        change_time=now,
        change_desc="creating new user {} [{}]".format(
            new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_change)
    new_log = SystemLog(
        event_code=SystemLogEventCode.UserCreate,
        event_time=now,
        event_desc="creating new user {} [{}]".format(
            new_user.username, new_user.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_log)

    db.session.commit()


def execute_login(user, login_function=None):
    """
    Record a login and execute a provided login function if the supplied
    credentials are correct.
    """
    pass