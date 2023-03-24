from flask_login import UserMixin

from . import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    avatar_url = db.Column(db.String(1000))
    header_image_url = db.Column(db.String(1000))
    header_text = db.Column(db.String(256))
    card_image_url = db.Column(db.String(1000))
    alternate_email = db.Column(db.String(100))
    email_verified = db.Column(db.Boolean)
    alternate_email_verified = db.Column(db.Boolean)
    description = db.Column(db.String(10000))
    created_time = db.Column(db.DateTime)
    modified_time = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean)


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


class PostedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_time = db.Column(db.DateTime)
    post_content = db.Column(db.String(1024))
    reply_to = db.Column(db.Integer)  # id of message replied to if any
    repost_id = db.Column(db.Integer)  # id of message being reposted if any
    deleted = db.Column(db.Boolean)


# strings between colons like :<string>: are emoji strings
class Emoji(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    added_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer)  # user that added the emoji
    name = db.Column(db.String(32))
    emoji_url = db.Column(db.String(1000))
    emoji_description = db.Column(db.String(1000))
    modified_time = db.Column(db.DateTime)


class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_id = db.Column(db.Integer)
    reaction_time = db.Column(db.DateTime)
    emoji_id = db.Column(db.Integer)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    created_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer)  # user that first used the tag
    tag_description = db.Column(db.String(1000))
    modified_time = db.Column(db.DateTime)
    last_used_time = db.Column(db.DateTime)


class HashTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    tag_id = db.Column(db.Integer)
