from flask_login import UserMixin

from . import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True)
    password = db.Column(db.String(1024))
    name = db.Column(db.String(1024))
    avatar_url = db.Column(db.String(1024))
    header_image_url = db.Column(db.String(1024))
    header_text = db.Column(db.String(256))
    card_image_url = db.Column(db.String(1024))
    alternate_email = db.Column(db.String(128))
    email_verified = db.Column(db.Boolean)
    alternate_email_verified = db.Column(db.Boolean)
    description = db.Column(db.String(10240))
    created_time = db.Column(db.DateTime)
    modified_time = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean)
    last_login = db.Column(db.DateTime)
    last_login_addr = db.Column(db.String(256))
    view_count = db.Column(db.Integer)
    post_view_count = db.Column(db.Integer)
    username = db.Column(db.String(128))  # should be unique!!! but sqlite doesn't like the constraint since it can't alter table
    post_count = db.Column(db.Integer)


class UserChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    change_code = db.Column(db.Integer)
    change_time = db.Column(db.DateTime)
    change_desc = db.Column(db.String(256))
    referrer = db.Column(db.String(256))
    user_agent = db.Column(db.String(512))
    remote_addr = db.Column(db.String(256))
    endpoint = db.Column(db.String(128))


class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_code = db.Column(db.Integer)
    event_time = db.Column(db.DateTime)
    event_desc = db.Column(db.String(256))
    referrer = db.Column(db.String(256))
    user_agent = db.Column(db.String(512))
    remote_addr = db.Column(db.String(256))
    endpoint = db.Column(db.String(128))


class PostedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_time = db.Column(db.DateTime)
    post_content = db.Column(db.String(1024))
    reply_to = db.Column(db.Integer)  # id of message replied to if any
    repost_id = db.Column(db.Integer)  # id of message being reposted if any
    deleted = db.Column(db.Boolean)
    view_count = db.Column(db.Integer)


class PostedMessageView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    view_time = db.Column(db.DateTime)
    current_user = db.Column(db.String(256))
    referrer = db.Column(db.String(256))
    user_agent = db.Column(db.String(512))
    remote_addr = db.Column(db.String(256))
    endpoint = db.Column(db.String(128))


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
    deleted = db.Column(db.Boolean)


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
    post_time = db.Column(db.DateTime)


class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    file_path = db.Column(db.String(256), unique=True)  # relative to the upload archive directory
    preview_path = db.Column(db.String(256), unique=True)  # relative to upload dir too
    description = db.Column(db.String(1024))
    created_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer)
    deleted = db.Column(db.Boolean)
    view_count = db.Column(db.Integer)


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_file_id = db.Column(db.Integer)
    post_id = db.Column(db.Integer)


class Mention(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_id = db.Column(db.Integer)


class GlobalSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    var = db.Column(db.String(128), unique=True)
    val = db.Column(db.String(256)) 


# TODO: notifications table


# TODO: mentions table to keep track of user mentions in posts.
# Extract all emails from each post when entering it in the DB
# and check if the email has been registered then add it to mentions
# table. We assume that mentions before the email is registered
# are lost.

# TODO: statistics table. Start with a post count and user count
# increment.
