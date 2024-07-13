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


SystemLogEventCode = IntEnum(
    'SystemLogEventCode',
    ['UserLogin', 'UserCreate', 'UserLogout', 'SettingChange'])

UserChangeEventCode = IntEnum(
    'UserChangeEventCode',
    ['UserLogin', 'UserCreate', 'UserLogout'])

ErrorCode = IntEnum(
    'ErrorCode',
    ['EmailExists', 'UsernameExists', 'InvalidEmail'])


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
        set_setting(var_name, default)
        return default

    return None


def set_setting(var_name, value):
    """
    Sets a setting to the global settings table.
    """
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


def register_user(
        username, password, name, email, request, cur_time=None):
        # if this returns a user, then the email already exists in database
        user = User.query.filter_by(email=email).first()

        # if a user is found, we want to redirect back to register page so
        # user can try again
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
        try:
            emailinfo = validate_email(
                email, check_deliverability=True)
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