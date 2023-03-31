from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for

from flask_login import current_user, login_required, login_user, logout_user

from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .models import SystemLog, User, UserChange


auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it
    # to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        # if the user doesn't exist or password is wrong, reload the page
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)
    now = datetime.now()
    user.last_login = now
    new_log = SystemLog(
        event_code=31337,  # default for now
        event_time=now,
        event_desc="user {} [{}] logged in".format(
            user.email, user.id))
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for('main.user_view', email=user.email))


@auth.route('/register')
def register():
    return render_template('register.html')


@auth.route('/register', methods=['POST'])
def register_post():
    # code to validate and add user to database goes here
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    # if a user is found, we want to redirect back to register page so
    # user can try again
    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.register'))

    # create a new user with the form data. Hash the password so the
    # plaintext version isn't saved.
    now = datetime.now()
    new_user = User(
        email=email, name=name,
        password=generate_password_hash(password, method='sha256'),
        created_time=now,
        modified_time=now,
        avatar_url="/assets/img/atxcf_logo_small.jpg",
        card_image_url="/assets/img/20200126_atxcf_bg_sq-1.png",
        header_image_url="/assets/img/20200126_atxcf_bg_sq-1.png",
        header_text=name,
        description="{} is on the scene".format(name),
        email_verified=False,
        is_admin=False,
        last_login=None)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()  # commit now to create new user id

    new_change = UserChange(
        user_id=new_user.id,
        change_code=31337,  # default for now
        change_time=now,
        change_desc="creating new user {} [{}]".format(
            new_user.email, new_user.id))
    db.session.add(new_change)
    new_log = SystemLog(
        event_code=31337,  # default for now
        event_time=now,
        event_desc="creating new user {} [{}]".format(
            new_user.email, new_user.id))
    db.session.add(new_log)

    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    new_log = SystemLog(
        event_code=31337,  # default for now
        event_time=datetime.now(),
        event_desc="user {} [{}] logging out".format(
            current_user.email, current_user.id))
    db.session.add(new_log)
    db.session.commit()
    logout_user()
    return redirect(url_for('main.index'))
