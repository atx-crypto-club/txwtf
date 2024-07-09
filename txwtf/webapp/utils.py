import logging

from . import db
from .models import GlobalSettings


DEFAULT_SITE_LOGO = "/assets/img/atxcf_logo_small.jpg"
DEFAULT_CARD_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"
DEFAULT_HEADER_IMAGE = "/assets/img/20200126_atxcf_bg_sq-1.png"


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


def get_default_card_image(default=DEFAULT_CARD_IMAGE):
    return get_setting("default_card", default)


def get_default_header_image(default=DEFAULT_HEADER_IMAGE):
    return get_setting("default_header", default)
