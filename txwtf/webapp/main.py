import os

from flask import (
    Blueprint, render_template, send_from_directory, request, flash, redirect, url_for)

from flask_login import current_user, login_required

from . import avatars

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


@main.route('/assets/<path:path>')
def send_report(path):
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
        saved_name = avatars.save(request.files["avatar"], folder=str(current_user.id))
        flash("Avatar saved successfully as {}.".format(saved_name))
        return redirect(url_for("main.profile"))
