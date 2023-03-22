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

from .models import UserChange, SystemLog


main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    if current_user.header_image_url is None:
        header_image_url = "/assets/img/20200126_atxcf_bg_sq-1.png"
    else:
        header_image_url = current_user.header_image_url

    if current_user.card_image_url is None:
        card_image_url = "/assets/img/20200126_atxcf_bg_sq-1.png"
    else:
        card_image_url = current_user.card_image_url

    if current_user.avatar_url is None:
        avatar_url = "/assets/img/atxcf_logo_small.jpg"
    else:
        avatar_url = current_user.avatar_url

    if current_user.created_time is None:
        created_time = str(datetime.now().ctime())
    else:
        created_time = current_user.created_time.ctime()

    if current_user.modified_time is None:
        modified_time = str(datetime.now().ctime())
    else:
        modified_time = current_user.modified_time.ctime()

    admins = current_app.config['ADMINISTRATORS']
    if current_user.email in admins:
        is_admin = True
    else:
        is_admin = False

    if current_user.header_text is None:
        header_text = "Welcome, {}".format(current_user.name)
    else:
        header_text = current_user.header_text

    if current_user.email_verified:
        email_verification = "verified"
    else:
        email_verification = "unverified"

    return render_template(
        'profile.html', name=current_user.name,
        header_image_url=header_image_url, avatar_url=avatar_url,
        email=current_user.email, description=current_user.description,
        description_markdown=markdownify(current_user.description),
        created_time=created_time, modified_time=modified_time,
        is_admin=is_admin, header_text=header_text,
        header_text_markdown=markdownify(header_text),
        email_verification=email_verification, 
        card_image_url=card_image_url)


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
            return redirect(url_for("main.profile"))
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
            event_desc="Uploaded {}".format(saved_name))
        db.session.add(new_log)
        db.session.commit()
        flash("Avatar saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} avatar image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.profile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.profile"))


@main.route("/upload-header-image", methods=['POST'])
@login_required
def upload_header_image():
    if "header_image" in request.files:
        if request.files["header_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.profile"))
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
        return redirect(url_for("main.profile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.profile"))


@main.route("/upload-card-image", methods=['POST'])
@login_required
def upload_card_image():
    if "card_image" in request.files:
        if request.files["card_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.profile"))
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
        return redirect(url_for("main.profile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.profile"))
    

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
    return redirect(url_for("main.profile"))


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
    return redirect(url_for("main.profile"))


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
    return redirect(url_for("main.profile"))


@main.route('/uploads/<path:path>')
def uploads(path):
    return send_from_directory(
        current_app.config["UPLOADED_ARCHIVE_DEST"], path)
