from datetime import datetime
import logging
import os

from flask import (
    Blueprint, render_template, send_from_directory, request,
    flash, redirect, url_for, current_app)

from flask_login import current_user, login_required

from markdown import markdown

from markdownify import markdownify

from . import db, upload_archive

from .models import User, UserChange, SystemLog, PostedMessage


main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/edit-profile')
@login_required
def editprofile():
    changes = db.session.query(UserChange).filter(
        UserChange.user_id == current_user.id).order_by(
            UserChange.change_time.desc())
    return render_template(
        'editprofile.html', changes=changes)


def generate_render_post_data(dbposts):
    posts = []
    logged_in = hasattr(current_user, 'email_verified')  # janky but whatev
    for dbpost in dbposts:
        class PostInfo(object):
            pass
        post = PostInfo()
        user = db.session.query(User).filter(User.id == dbpost.user_id).first()
        post.user_id = user.id
        post.avatar_url = user.avatar_url
        post.name = user.name
        # hide email addresses of users if not logged in.
        if not logged_in:
            post.email = ""
        else:
            post.email = user.email
        post.post_time = dbpost.post_time
        post.post_content = dbpost.post_content
        post.id = dbpost.id
        post.deleted = dbpost.deleted
        post.num_reposts = len(db.session.query(PostedMessage).filter(
            PostedMessage.repost_id == dbpost.id).all())
        post.replies = generate_render_post_data(
            db.session.query(PostedMessage).filter(
                PostedMessage.reply_to == dbpost.id).all())
        post.num_replies = len(post.replies)

        if dbpost.repost_id:
            dbrepost = db.session.query(PostedMessage).filter(
                PostedMessage.id == dbpost.repost_id)
            post.repost = generate_render_post_data(dbrepost)[0]

        posts.append(post)
    return posts


@main.route('/u/<email>')
@login_required
def user_view(email):
    user = db.session.query(User).filter(User.email == email).first()
    if user is None:
        return render_template('error.html', error_msg='Unknown user!')

    # get post messages for this user
    dbposts = db.session.query(PostedMessage).filter(
        PostedMessage.user_id == user.id).order_by(
            PostedMessage.post_time.desc()).all()
    
    posts = generate_render_post_data(dbposts)
    return render_template('users.html', user=user, posts=posts)


@main.route('/user-list')
@login_required
def user_list():
    return render_template(
        'userlist.html',
        users=db.session.query(User).order_by(
            User.modified_time.desc()).all())


@main.route('/system-log')
@login_required
def system_log():
    if not current_user.is_admin:
        return render_template('unauthorized.html'), 401
    logs = db.session.query(SystemLog).order_by(SystemLog.event_time.desc())
    return render_template('systemlog.html', logs=logs)


@main.route('/about')
def about():
    return render_template('about.html')


def render_post(
        post, show_level_menu=True, show_delete_button=True,
        show_repost=True, show_replies=True, show_deleted_replies=False):
    return render_template(
        'post_fragment.html', post=post,
        show_level_menu=show_level_menu,
        show_delete_button=show_delete_button,
        show_repost=show_repost, show_replies=show_replies,
        show_deleted_replies=show_deleted_replies)


def render_posts(
        posts, show_post_message_button=True,
        show_level_menu=True, show_deleted=False,
        show_replies=True, show_deleted_replies=False):
    return render_template(
        'posts_fragment.html', posts=posts,
        show_level_menu=show_level_menu,
        show_post_message_button=show_post_message_button,
        show_deleted=show_deleted, show_replies=show_replies,
        show_deleted_replies=show_deleted_replies)


def render_post_message(post_content=""):
    return render_template(
        'post_message_fragment.html', post_content=post_content)


def render_user_card(user):
    return render_template('user_card_fragment.html', user=user)


# TODO: add thread route to view a post with it's reply_to posts


@main.route('/posts')
def posts():
    # TODO: paginate post rendering by limiting
    # range of posts to render by min/max time
    # TODO: use a join to speed this query up
    # TODO: hide reply_to posts
    # TODO: if you click on a post, go to the thread route
    dbposts = db.session.query(PostedMessage).order_by(PostedMessage.post_time.desc())
    posts = generate_render_post_data(dbposts)
    return render_template('posts.html', posts=posts)


@main.route('/post-message', methods=['POST'])
@login_required
def post_message():
    redirect_url = request.form.get('redirect')
    reply_to = request.form.get('reply_to')
    repost_id = request.form.get('repost_id')
    if reply_to == "":
        reply_to = None
    if repost_id == "":
        repost_id = None

    # TODO: extract all hash tags and add them to the tables
    
    post_content = markdown(request.form.get('post_content'))
    if len(post_content) == 0:
        flash('Error: Empty post!')
        return redirect(redirect_url)

    # TODO: extract all emoji strings and replace them with inline
    # images in the post_content after generating html from markdown

    # TODO: we should do validation on the reply_to and repost_ids
    # to make sure that this user has access to the post when we
    # introduce the concept of follows and friends and the post is
    # flagged private

    msg = PostedMessage(
        user_id=current_user.id,
        post_time=datetime.now(),
        post_content=post_content,
        reply_to=reply_to,
        repost_id=repost_id,
        deleted=False)
    db.session.add(msg)
    db.session.commit()
    flash("Message posted!")
    return redirect(redirect_url)


@main.route('/delete-post', methods=['POST'])
@login_required
def delete_post():
    post_id = request.form.get('post_id')
    post = db.session.query(PostedMessage).filter(
        PostedMessage.id == int(post_id)).first()
    if post.user_id != current_user.id:
        logger.error("Unauthorized post delete: {} {}".format(
            post.user_id, current_user.id))
        return render_template(
            'error.html', error_msg="Unauthorized post delete"), 401
    post.deleted = True
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337, # default for now
        change_time=datetime.now(),
        change_desc="deleted post {}".format(
            current_user.email, post.id))
    db.session.add(new_change)
    new_log = SystemLog(
        event_code=31337, # default for now
        event_time=datetime.now(),
        event_desc="User {} deleted post {}".format(
            current_user.email, post.id))
    db.session.add(new_log)
    db.session.commit()
    return "OK"


@main.route('/assets/<path:path>')
def assets(path):
    return send_from_directory('assets', path)


@main.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(main.root_path, 'assets', 'img'),
        'cropped-atxcf_logo_small-32x32.jpg')


@main.route("/upload-avatar", methods=['POST'])
@login_required
def upload_avatar():
    if "avatar" in request.files:
        if request.files["avatar"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["avatar"],
            folder=str(current_user.email))
        current_user.avatar_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337, # default for now
            change_time=datetime.now(),
            change_desc="Changing avatar to: {}".format(saved_name))
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337, # default for now
            event_time=datetime.now(),
            event_desc="User {} Uploaded {}".format(current_user.email, saved_name))
        db.session.add(new_log)
        db.session.commit()
        flash("Avatar saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} avatar image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))


@main.route("/upload-header-image", methods=['POST'])
@login_required
def upload_header_image():
    if "header_image" in request.files:
        if request.files["header_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["header_image"],
            folder=str(current_user.email))
        current_user.header_image_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337, # default for now
            change_time=datetime.now(),
            change_desc="Changing header to: {}".format(saved_name))
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337, # default for now
            event_time=datetime.now(),
            event_desc="Uploaded {}".format(saved_name))
        db.session.add(new_log)
        db.session.commit()
        flash("Header image saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} header image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))


@main.route("/upload-card-image", methods=['POST'])
@login_required
def upload_card_image():
    if "card_image" in request.files:
        if request.files["card_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["card_image"],
            folder=str(current_user.email))
        current_user.card_image_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337, # default for now
            change_time=datetime.now(),
            change_desc="Changing card image to: {}".format(saved_name))
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337, # default for now
            event_time=datetime.now(),
            event_desc="Uploaded {}".format(saved_name))
        db.session.add(new_log)
        db.session.commit()
        flash("Card image saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} card image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))
    

@main.route("/update-user-description", methods=['POST'])
@login_required
def update_user_description():
    desc = request.form.get('user_description')
    current_user.description = markdown(desc)
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337, # default for now
        change_time=datetime.now(),
        change_desc="Changing description to: {}".format(desc))
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} description to: {}".format(
        current_user.email, desc))
    return redirect(url_for("main.editprofile"))


@main.route("/update-user-name", methods=['POST'])
@login_required
def update_user_name():
    name = request.form.get('name')
    current_user.name = name
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337, # default for now
        change_time=datetime.now(),
        change_desc="Changing name to: {}".format(name))
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} name to: {}".format(
        current_user.email, name))
    return redirect(url_for("main.editprofile"))


@main.route("/update-user-header-text", methods=['POST'])
@login_required
def update_user_header_text():
    header_text = request.form.get('user_header_text')
    current_user.header_text = markdown(header_text)
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337, # default for now
        change_time=datetime.now(),
        change_desc="Changing header text to: {}".format(header_text))
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} header text to: {}".format(
        current_user.email, header_text))
    return redirect(url_for("main.editprofile"))


@main.route('/uploads/<path:path>')
def uploads(path):
    return send_from_directory(
        current_app.config["UPLOADED_ARCHIVE_DEST"], path)
