import logging

from . import db
from .models import GlobalSettings


def get_setting_record(var_name):
    return db.session.query(GlobalSettings).filter(
        GlobalSettings.var == var_name).first()


def get_setting(var_name):
    setting = get_setting_record(var_name)
    if setting:
        return setting.val
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
        value=value)
    db.session.add(setting)
    db.session.commit()


def get_site_logo(default="/assets/img/atxcf_logo_small.jpg"):
    site_logo = get_setting("site_logo")
    if site_logo:
        return site_logo
    site_logo = default
    set_setting("site_logo", site_logo)
    return site_logo


def get_default_card_image(default="/assets/img/20200126_atxcf_bg_sq-1.png"):
    default_card = get_setting("default_card")
    if default_card:
        return default_card
    default_card = default
    set_setting("default_card", default_card)
    return default_card


def get_default_header_image(default="/assets/img/20200126_atxcf_bg_sq-1.png"):
    default_header = get_setting("default_header")
    if default_header:
        return default_header
    default_header = default
    set_setting("default_header", default_header)
    return default_header
