from flask_login import UserMixin

from . import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    avatar_url = db.Column(db.String(1000))
    header_image_url = db.Column(db.String(1000))
    card_image_url = db.Column(db.String(1000))
    alternate_email = db.Column(db.String(100))
    email_verified = db.Column(db.Boolean)
    alternate_email_verified = db.Column(db.Boolean)
    description = db.Column(db.String(10000))
    created_time = db.Column(db.DateTime)
    modified_time = db.Column(db.DateTime)


class UserChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    change_code = db.Column(db.Integer)
    change_time = db.Column(db.DateTime)
    change_desc = db.Column(db.String(256))


class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_code = db.Column(db.Integer)
    event_time = db.Column(db.DateTime)
    event_desc = db.Column(db.String(256))
