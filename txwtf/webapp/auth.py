from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for

from flask_login import current_user, login_required, login_user, logout_user

from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .models import User, UserChange, SystemLog


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
    new_log = SystemLog(
        event_code=31337, # default for now
        event_time=datetime.now(),
        event_desc="user {} [{}] logged in".format(
            user.email, user.id))
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for('main.profile'))


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
    new_user = User(
        email=email, name=name,
        password=generate_password_hash(password, method='sha256'),
        created_time=datetime.now(),
        modified_time=datetime.now())

    # add the new user to the database
    db.session.add(new_user)

    new_change = UserChange(
        user_id=new_user.id,
        change_code=31337, # default for now
        change_time=datetime.now(),
        change_desc="creating new user {} [{}]".format(
        new_user.email, new_user.id))
    db.session.add(new_change)
    new_log = SystemLog(
        event_code=31337, # default for now
        event_time=datetime.now(),
        event_desc="creating new user {} [{}]".format(
        new_user.email, new_user.id))
    db.session.add(new_log)

    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    new_log = SystemLog(
        event_code=31337, # default for now
        event_time=datetime.now(),
        event_desc="user {} [{}] logging out".format(
            current_user.email, current_user.id))
    db.session.add(new_log)
    db.session.commit()
    logout_user()
    return redirect(url_for('main.index'))
