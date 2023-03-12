from flask import Blueprint, render_template, send_from_directory

from flask_login import current_user, login_required

# from . import db

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
