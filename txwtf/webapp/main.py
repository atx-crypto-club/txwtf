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


@main.route('/u/<email>')
@login_required
def user_view(email):
    user = db.session.query(User).filter(User.email == email).first()
    if user is None:
        return render_template('error.html', error_msg='Unknown user!')

    # get post messages for this user
    posts = db.session.query(PostedMessage).filter(
        PostedMessage.user_id == user.id).order_by(
            PostedMessage.post_time.desc()).all()

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


@main.route('/posts')
def posts():
    dbposts = db.session.query(PostedMessage).order_by(PostedMessage.post_time.desc())
    posts = []
    logged_in = hasattr(current_user, 'email_verified')
    for dbpost in dbposts:
        class PostInfo(object):
            pass
        post = PostInfo()
        user = db.session.query(User).filter(User.id == dbpost.user_id).first()
        post.avatar_url = user.avatar_url
        if post.avatar_url is None:
            post.avatar_url = "/assets/img/atxcf_logo_small.jpg"
        post.name = user.name
        if not logged_in:
            post.email = ""
        else:
            post.email = user.email
        post.post_time = dbpost.post_time
        post.post_content = dbpost.post_content
        posts.append(post)
    
    return render_template('posts.html', posts=posts)


@main.route('/post-message', methods=['POST'])
@login_required
def post_message():
    redirect_url = request.form.get('redirect')
    post_content = markdown(request.form.get('post_content'))
    msg = PostedMessage(
        user_id=current_user.id,
        post_time=datetime.now(),
        post_content=post_content)
    db.session.add(msg)
    db.session.commit()
    flash("Message posted!")
    return redirect(redirect_url)


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
