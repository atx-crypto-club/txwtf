from datetime import datetime
import unittest

from flask_testing import TestCase

import email_validator

from werkzeug.security import check_password_hash, generate_password_hash

from txwtf.webapp import create_app, db
from txwtf.webapp.models import User, UserChange, SystemLog
from txwtf.webapp.utils import (
    get_setting, set_setting, get_site_logo,
    get_default_avatar, get_default_card_image,
    get_default_header_image, register_user,
    DEFAULT_SITE_LOGO, DEFAULT_AVATAR,
    DEFAULT_CARD_IMAGE, DEFAULT_HEADER_IMAGE,
    UserChangeEventCode, RegistrationError, 
    ErrorCode, SystemLogEventCode)


# Turn off DNS validation for tests
email_validator.TEST_ENVIRONMENT = True


class FakeRequest(object):
    def __init__(self, **kwargs):
        self.referrer = kwargs["referrer"]
        self.user_agent = kwargs["user_agent"]
        self.endpoint = kwargs["endpoint"]
        self.remote_addr = kwargs["remote_addr"]
        self.headers = kwargs["headers"]


class TestWebappUtils(TestCase):

    SQLALCHEMY_DATABASE_URI = "sqlite://"
    TESTING = True

    def create_app(self):
        return create_app(self)

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_get_setting_default(self):
        """
        Test that get setting returns None when no setting is available.
        """
        # when
        val = get_setting("nothing")

        # then
        self.assertIsNone(val)

    def test_get_setting(self):
        """
        Test that get setting returns what is set.
        """
        # with
        var = "test_setting"
        val = "value"

        # when
        set_setting(var, val)

        # then
        self.assertEqual(get_setting(var), val)

    def test_site_logo(self):
        """
        Test default site logo setting.
        """
        self.assertEqual(get_site_logo(), DEFAULT_SITE_LOGO)

    def test_site_logo_change(self):
        """
        Test changing site logo setting.
        """
        # with
        site_logo = "test.png"

        # when
        set_setting("site_logo", site_logo)

        # then
        self.assertEqual(get_site_logo(), site_logo)

    def test_default_avatar(self):
        """
        Test default avatar setting.
        """
        self.assertEqual(get_default_avatar(), DEFAULT_AVATAR)

    def test_default_avatar_change(self):
        """
        Test changing default avatar setting.
        """
        # with
        avatar = "test.png"

        # when
        set_setting("default_avatar", avatar)

        # then
        self.assertEqual(get_default_avatar(), avatar)

    def test_default_card_image(self):
        """
        Test default card image setting.
        """
        self.assertEqual(get_default_card_image(), DEFAULT_CARD_IMAGE)

    def test_default_card_image_change(self):
        """
        Test changing card image setting.
        """
        # with
        default_card = "test.png"

        # when
        set_setting("default_card", default_card)

        # then
        self.assertEqual(get_default_card_image(), default_card)

    def test_default_header_image(self):
        """
        Test default header image setting.
        """
        self.assertEqual(get_default_header_image(), DEFAULT_HEADER_IMAGE)

    def test_default_header_image_change(self):
        """
        Test changing header image setting.
        """
        # with
        default_header = "test.png"

        # when
        set_setting("default_header", default_header)

        # then
        self.assertEqual(get_default_header_image(), default_header)

    def test_register_user(self):
        """
        Test registering a user.
        """
        # with
        username = "root"
        password = "password"
        name = "admin"
        email = "root@tx.wtf"
        referrer = "localhost"
        user_agent = "mozkillah 420.69"
        endpoint = "/register"
        remote_addr = "127.0.0.1"
        headers = {
            "X-Forwarded-For": "192.168.0.1"}
        cur_time = datetime.now()

        request = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint=endpoint, remote_addr=remote_addr,
            headers=headers)

        # when
        register_user(
            username, password, name, email, request, cur_time)
        
        # then
        ## check user
        user = db.session.query(User).first()
        self.assertEqual(user.email, email)
        self.assertEqual(user.name, name)
        self.assertTrue(
            check_password_hash(user.password, password))
        self.assertEqual(user.created_time, cur_time)
        self.assertEqual(user.modified_time, cur_time)
        self.assertEqual(
            user.avatar_url,get_default_avatar())
        self.assertEqual(
            user.card_image_url, get_default_card_image())
        self.assertEqual(
            user.header_image_url, get_default_header_image())
        self.assertEqual(user.header_text, name)
        self.assertEqual(
            user.description, "{} is on the scene".format(name))
        self.assertEqual(user.email_verified, False)
        self.assertEqual(user.is_admin, False)
        self.assertEqual(user.last_login, None)
        self.assertEqual(user.last_login_addr, None)
        self.assertEqual(user.view_count, 0)
        self.assertEqual(user.post_view_count, 0)
        self.assertEqual(user.username, username)
        self.assertEqual(user.post_count, 0)

        ## check logs
        new_change = db.session.query(UserChange).first()
        self.assertEqual(new_change.user_id, user.id)
        self.assertEqual(
            new_change.change_code, UserChangeEventCode.UserCreate)
        self.assertEqual(new_change.change_time, cur_time)
        self.assertEqual(
            new_change.change_desc,
            "creating new user {} [{}]".format(
                user.username, user.id))
        self.assertEqual(new_change.referrer, request.referrer)
        self.assertEqual(new_change.user_agent, request.user_agent)
        self.assertEqual(
            new_change.remote_addr, request.headers.get("X-Forwarded-For"))
        self.assertEqual(new_change.endpoint, request.endpoint)

        new_log = db.session.query(SystemLog).first()
        self.assertEqual(
            new_log.event_code, SystemLogEventCode.UserCreate)
        self.assertEqual(new_log.event_time, cur_time)
        self.assertEqual(
            new_log.event_desc,
            "creating new user {} [{}]".format(
                user.username, user.id))
        self.assertEqual(new_log.referrer, request.referrer)
        self.assertEqual(new_log.user_agent, request.user_agent)
        self.assertEqual(
            new_log.remote_addr, request.headers.get("X-Forwarded-For"))
        self.assertEqual(new_log.endpoint, request.endpoint)

    def test_register_email_exists(self):
        """
        Test that there is an error if an email already exists.
        """
        # with
        username = "root"
        password = "password"
        name = "admin"
        email = "root@tx.wtf"
        referrer = "localhost"
        user_agent = "mozkillah 420.69"
        endpoint = "/register"
        remote_addr = "127.0.0.1"
        headers = {
            "X-Forwarded-For": "192.168.0.1"}
        cur_time = datetime.now()

        request = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint=endpoint, remote_addr=remote_addr,
            headers=headers)

        # when
        register_user(
            username, password, name, email, request, cur_time)
        
        try:
            register_user(
                username, password, name, email, request, cur_time)
        except Exception as e:
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.EmailExists)

    def test_register_username_exists(self):
        """
        Test that there is an error if a username already exists.
        """
        # with
        username = "root"
        password = "password"
        name = "admin"
        email = "root@tx.wtf"
        referrer = "localhost"
        user_agent = "mozkillah 420.69"
        endpoint = "/register"
        remote_addr = "127.0.0.1"
        headers = {
            "X-Forwarded-For": "192.168.0.1"}
        cur_time = datetime.now()

        request = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint=endpoint, remote_addr=remote_addr,
            headers=headers)

        # when
        register_user(
            username, password, name, email, request, cur_time)
        
        try:
            # change the email to trigger a username error instead
            email = email + ".net"
            register_user(
                username, password, name, email,
                request, cur_time)
        except Exception as e:
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.UsernameExists)


if __name__ == '__main__':
    unittest.main()