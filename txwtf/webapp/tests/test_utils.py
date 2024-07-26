from datetime import datetime
import unittest

from flask_testing import TestCase

import email_validator

from werkzeug.security import check_password_hash, generate_password_hash

from txwtf.webapp import create_app, db
from txwtf.webapp.models import User, UserChange, SystemLog, GlobalSettings
from txwtf.webapp.utils import (
    get_setting_record, get_setting, set_setting, list_setting,
    has_setting, get_site_logo, get_default_avatar,
    get_default_card_image, get_default_header_image,
    get_password_special_symbols, get_password_min_length,
    get_password_max_length, get_password_special_symbols_enabled,
    get_password_min_length_enabled,
    get_password_max_length_enabled,
    get_password_digit_enabled,
    get_password_upper_enabled,
    get_password_lower_enabled,
    get_email_validate_deliverability_enabled,
    password_check, register_user, execute_login, execute_logout,
    SITE_LOGO, AVATAR,
    CARD_IMAGE, HEADER_IMAGE,
    PASSWORD_SPECIAL_SYMBOLS,
    PASSWORD_MINIMUM_LENGTH,
    PASSWORD_MAXIMUM_LENGTH,
    PASSWORD_SPECIAL_SYMBOLS_ENABLED,
    PASSWORD_MINIMUM_LENGTH_ENABLED,
    PASSWORD_MAXIMUM_LENGTH_ENABLED,
    PASSWORD_DIGIT_ENABLED,
    PASSWORD_UPPER_ENABLED,
    PASSWORD_LOWER_ENABLED,
    EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
    UserChangeEventCode, RegistrationError, LoginError,
    LogoutError, PasswordError, SettingsError, ErrorCode,
    SystemLogEventCode)


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
        code = None
        try:
            get_setting("nothing")
        except Exception as e:
            self.assertIsInstance(e, SettingsError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.SettingDoesntExist)
        self.assertFalse(has_setting("nothing"))

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
        self.assertTrue(has_setting(var))

    def test_get_setting_record_recursive(self):
        """
        Test that we can get child settings.
        """
        # with
        var0 = "test_root"
        val0 = "q"
        var1 = "test_nested"
        val1 = "r"

        # when
        now0 = datetime.now()
        setting0 = GlobalSettings(
            var=var0,
            val=val0,
            parent_id=None,
            created_time=now0,
            modified_time=now0,
            accessed_time=now0)
        db.session.add(setting0)
        db.session.commit()
        now1 = datetime.now()
        setting1 = GlobalSettings(
            var=var1,
            val=val1,
            parent_id=setting0.id,
            created_time=now1,
            modified_time=now1,
            accessed_time=now1)
        db.session.add(setting1)
        db.session.commit()

        # then
        self.assertEqual(
            setting0, get_setting_record(var0))

        code = None
        try:
            get_setting_record(var1)
        except Exception as e:
            self.assertIsInstance(e, SettingsError)
            code, _ = e.args
        self.assertEqual(code, ErrorCode.SettingDoesntExist)
        self.assertEqual(
            setting1,
            get_setting_record(var1, parent_id=setting0.id))
        self.assertEqual(setting1, get_setting_record(var0, var1))

    def test_get_setting_record_recursive_create(self):
        """
        Test that we can get child settings, creating
        records on demand.
        """
        # with
        var0 = "test_root"
        val0 = "q"
        var1 = "test_nested"
        val1 = "r"

        # when
        now0 = datetime.now()
        setting0 = GlobalSettings(
            var=var0,
            val=val0,
            parent_id=None,
            created_time=now0,
            modified_time=now0,
            accessed_time=now0)
        db.session.add(setting0)
        db.session.commit()

        # then
        setting1 = get_setting_record(
            var0, var1, create=True, default=val1,
            now=now0)
        self.assertIsNotNone(setting1)
        self.assertEqual(setting1.parent_id, setting0.id)
        self.assertEqual(setting1.val, val1)
        self.assertEqual(setting1.created_time, now0)

    def test_set_setting_child(self):
        """
        Test that we can get child settings.
        """
        # with
        var0 = "test_root"
        val0 = "q"
        var1 = "test_nested"
        val1 = "r"

        # when
        now = datetime.now()
        #import pdb; pdb.set_trace()
        set_setting(var0, val0)
        set_setting(var0, var1, val1)

        # then
        self.assertEqual(val0, get_setting(var0))
        self.assertEqual(val1, get_setting(var0, var1))
        self.assertTrue(has_setting(var0, var1))
        self.assertEqual(set(list_setting(var0)), {var1})
        self.assertEqual(set(list_setting(var0, var1)), set())

    def test_get_setting_parent_none(self):
        """
        Test verify that parent nodes return none
        """
        # with
        var0 = "test_root"
        val0 = "q"
        var1 = "test_nested"
        val1 = "r"

        # when
        set_setting(var0, var1, val1)

        # then
        self.assertIsNone(get_setting(var0))
        self.assertEqual(get_setting(var0, var1), val1)
        self.assertTrue(has_setting(var0, var1))

    def test_get_setting_parent_not_none(self):
        """
        Test verify that parent nodes can return a value
        """
        # with
        var0 = "test_root"
        val0 = "q"
        var1 = "test_nested"
        val1 = "r"

        # when
        set_setting(var0, var1, val1)
        set_setting(var0, val0)

        # then
        self.assertEqual(get_setting(var0), val0)
        self.assertEqual(get_setting(var0, var1), val1)
        self.assertTrue(has_setting(var0, var1))

    def test_site_logo(self):
        """
        Test default site logo setting.
        """
        #import pdb; pdb.set_trace()
        self.assertEqual(get_site_logo(), SITE_LOGO)

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
        self.assertEqual(get_default_avatar(), AVATAR)

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
        self.assertEqual(get_default_card_image(), CARD_IMAGE)

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
        self.assertEqual(get_default_header_image(), HEADER_IMAGE)

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

    def test_password_special_symbols(self):
        """
        Test default password special symbols setting.
        """
        self.assertEqual(
            get_password_special_symbols(), PASSWORD_SPECIAL_SYMBOLS)

    def test_password_special_symbols_change(self):
        """
        Test changing password special symbols setting.
        """
        # with
        special_sym = "$%^&"

        # when
        set_setting("password_special_symbols", special_sym)

        # then
        self.assertEqual(get_password_special_symbols(), special_sym)

    def test_password_min_length(self):
        """
        Test default password minimumm length.
        """
        self.assertEqual(
            get_password_min_length(), PASSWORD_MINIMUM_LENGTH)

    def test_password_min_length_change(self):
        """
        Test changing password minimum length setting.
        """
        # with
        min_length = 10

        # when
        set_setting("password_minimum_length", min_length)

        # then
        self.assertEqual(get_password_min_length(), min_length)

    def test_password_max_length(self):
        """
        Test default password maximum length.
        """
        self.assertEqual(
            get_password_max_length(), PASSWORD_MAXIMUM_LENGTH)

    def test_password_max_length_change(self):
        """
        Test changing password maximum length setting.
        """
        # with
        max_length = 128

        # when
        set_setting("password_maximum_length", max_length)

        # then
        self.assertEqual(get_password_max_length(), max_length)

    def test_password_special_symbols_enabled(self):
        """
        Test default password special symbols enabled flag.
        """
        self.assertEqual(
            get_password_special_symbols_enabled(),
            PASSWORD_SPECIAL_SYMBOLS_ENABLED)

    def test_password_special_symbols_enabled_change(self):
        """
        Test changing password special symbols enabled flag setting.
        """
        # with
        special_symbols_enabled = 0

        # when
        set_setting(
            "password_special_symbols_enabled",
            special_symbols_enabled)

        # then
        self.assertEqual(
            get_password_special_symbols_enabled(),
            special_symbols_enabled)

    def test_password_min_length_enabled(self):
        """
        Test default password min length enabled flag.
        """
        self.assertEqual(
            get_password_min_length_enabled(),
            PASSWORD_MINIMUM_LENGTH_ENABLED)

    def test_password_min_length_enabled_change(self):
        """
        Test changing password min length enabled flag setting.
        """
        # with
        min_length_enabled = 0

        # when
        set_setting(
            "password_minimum_length_enabled", 
            min_length_enabled)

        # then
        self.assertEqual(
            get_password_min_length_enabled(),
            min_length_enabled)

    def test_password_max_length_enabled(self):
        """
        Test default password max length enabled flag.
        """
        self.assertEqual(
            get_password_max_length_enabled(),
            PASSWORD_MAXIMUM_LENGTH_ENABLED)

    def test_password_max_length_enabled_change(self):
        """
        Test changing password max length enabled flag setting.
        """
        # with
        max_length_enabled = 0

        # when
        set_setting(
            "password_maximum_length_enabled",
            max_length_enabled)

        # then
        self.assertEqual(
            get_password_max_length_enabled(),
            max_length_enabled)

    def test_password_digit_enabled(self):
        """
        Test default password digit enabled flag.
        """
        self.assertEqual(
            get_password_digit_enabled(),
            PASSWORD_DIGIT_ENABLED)

    def test_password_digit_enabled_change(self):
        """
        Test changing password digit enabled flag setting.
        """
        # with
        digit_enabled = 0

        # when
        set_setting("password_digit_enabled", digit_enabled)

        # then
        self.assertEqual(get_password_digit_enabled(), digit_enabled)

    def test_password_upper_enabled(self):
        """
        Test default password upper enabled flag.
        """
        self.assertEqual(
            get_password_upper_enabled(),
            PASSWORD_UPPER_ENABLED)

    def test_password_uppper_enabled_change(self):
        """
        Test changing password upper enabled flag setting.
        """
        # with
        upper_enabled = 0

        # when
        set_setting("password_upper_enabled", upper_enabled)

        # then
        self.assertEqual(get_password_upper_enabled(), upper_enabled)

    def test_password_lower_enabled(self):
        """
        Test default password lower enabled flag.
        """
        self.assertEqual(
            get_password_lower_enabled(),
            PASSWORD_LOWER_ENABLED)

    def test_password_lower_enabled_change(self):
        """
        Test changing password lower enabled flag setting.
        """
        # with
        lower_enabled = 0

        # when
        set_setting("password_lower_enabled", lower_enabled)

        # then
        self.assertEqual(get_password_lower_enabled(), lower_enabled)

    def test_email_validate_deliverability_enabled(self):
        """
        Test default email validate deliverability enabled flag.
        """
        self.assertEqual(
            get_email_validate_deliverability_enabled(),
            EMAIL_VALIDATE_DELIVERABILITY_ENABLED)

    def test_email_validate_deliverability_enabled_change(self):
        """
        Test email validate deliverability enabled flag setting.
        """
        # with
        enabled = 0

        # when
        set_setting("email_validate_deliverability_enabled", enabled)

        # then
        self.assertEqual(
            get_email_validate_deliverability_enabled(), enabled)

    def test_password_check(self):
        """
        Test that password checking works as expected with default flags.
        """
        # with
        password = "asDf1234#!1"

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_error_min_length(self):
        """
        Test that password checking fails on default min length.
        """
        # with
        password = "aD1#!1"

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordTooShort)

    def test_password_check_error_max_length(self):
        """
        Test that password checking fails on default max length.
        """
        # with
        password = "asDf1234#!1"
        set_setting("password_maximum_length", 8)

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordTooLong)

    def test_password_check_error_missing_digit(self):
        """
        Test that password checking fails on missing digit.
        """
        # with
        password = "asDfFDSA#!!"

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordMissingDigit)

    def test_password_check_error_missing_upper(self):
        """
        Test that password checking fails on missing upper case character.
        """
        # with
        password = "asdf1234#!1"

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordMissingUpper)

    def test_password_check_error_missing_lower(self):
        """
        Test that password checking fails on missing lower case character.
        """
        # with
        password = "ASDF1234#!1"

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordMissingLower)

    def test_password_check_error_missing_symbol(self):
        """
        Test that password checking fails on missing symbol.
        """
        # with
        password = "asDf1234131"

        # when
        code = None
        try:
            password_check(password)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args

        # then
        self.assertEqual(code, ErrorCode.PasswordMissingSymbol)

    def test_password_check_symbol_disabled(self):
        """
        Test that password checking works with symbol flag disabled.
        """
        # with
        password = "asDf1234!1"
        set_setting("password_special_symbols_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_symbol_disabled_when_empty(self):
        """
        Test that password checking works when no special
        symbols are specified.
        """
        # with
        password = "asDf1234!1"
        set_setting("password_special_symbols", "")

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_min_length_disabled(self):
        """
        Test that password checking works with min length flag disabled.
        """
        # with
        password = "Aa#4!1"
        set_setting("password_minimum_length", 10)
        set_setting("password_minimum_length_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_max_length_disabled(self):
        """
        Test that password checking works with max length flag disabled.
        """
        # with
        password = "Aa#4!1"
        set_setting("password_minimum_length", 1)
        set_setting("password_maximum_length", 4)
        set_setting("password_maximum_length_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_digit_disabled(self):
        """
        Test that password checking works with digit flag disabled.
        """
        # with
        password = "asDffdsa#!1"
        set_setting("password_digit_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_upper_disabled(self):
        """
        Test that password checking works with upper flag disabled.
        """
        # with
        password = "asdffdsa#!1"
        set_setting("password_upper_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_password_check_lower_disabled(self):
        """
        Test that password checking works with lower flag disabled.
        """
        # with
        password = "ASDFFDSA#!1"
        set_setting("password_lower_enabled", 0)

        # when
        success = True
        try:
            password_check(password)
        except:
            success = False

        # then
        self.assertTrue(success)

    def test_register_user(self):
        """
        Test registering a user.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
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
            username, password, password, name, email,
            request, cur_time)
        
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
        password = "asDf1234#!1"
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
            username, password, password, name, email,
            request, cur_time)
        
        code = None
        try:
            register_user(
                username, password, password, name,
                email, request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, RegistrationError)
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.EmailExists)

    def test_register_username_exists(self):
        """
        Test that there is an error if a username already exists.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
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
            username, password, password, name, email,
            request, cur_time)
        
        code = None
        try:
            # change the email to trigger a username error instead
            email = email + ".net"
            register_user(
                username, password, password, name, email,
                request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, RegistrationError)
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.UsernameExists)

    def test_register_invalid_email(self):
        """
        Test that there is an error if an unallowed test email is used
        for registration.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
        name = "admin"
        email = "root@localhost"
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
        code = None
        try:
            register_user(
                username, password, password, name, email,
                request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, RegistrationError)
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.InvalidEmail)

    def test_register_invalid_email_2(self):
        """
        Test that there is an error if a malformed email is used
        for registration.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
        name = "admin"
        email = "root@localhost .com"
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
        code = None
        try:
            register_user(
                username, password, password, name, email,
                request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, RegistrationError)
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.InvalidEmail)

    def test_register_password_mismatch(self):
        """
        Test that there is an error if the password and
        verify_password don't match.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
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
        code = None
        try:
            register_user(
                username, password, password+"foo", name, email,
                request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, RegistrationError)
            code, _ = e.args
        
        self.assertEqual(code, ErrorCode.PasswordMismatch)

    def test_register_password_check_fail(self):
        """
        Test that there is an error if the password fails the password
        check.
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
        code = None
        try:
            register_user(
                username, password, password, name, email,
                request, cur_time)
        except Exception as e:
            self.assertIsInstance(e, PasswordError)
            code, _ = e.args
        
        self.assertIsNotNone(code)

    def test_execute_login(self):
        """
        Test registering then loggin in a user.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
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
            username, password, password, name, email,
            request, cur_time)
        
        request.endpoint = "/login"
        user = execute_login(
            username, password, request, cur_time=cur_time)

        # then
        ## check logs
        user_changes = db.session.query(UserChange).order_by(
            UserChange.id.desc())
        self.assertEqual(user_changes.count(), 2)
        last_user_change = user_changes.first()
        self.assertEqual(last_user_change.user_id, user.id)
        self.assertEqual(
            last_user_change.change_code,
            UserChangeEventCode.UserLogin)
        self.assertEqual(
            last_user_change.change_time, cur_time)
        self.assertEqual(
            last_user_change.change_desc,
            "logging in from {}".format(headers["X-Forwarded-For"]))
        self.assertEqual(
            last_user_change.referrer, request.referrer)
        self.assertEqual(
            last_user_change.user_agent, request.user_agent)
        self.assertEqual(
            last_user_change.remote_addr,
            request.headers.get("X-Forwarded-For"))
        self.assertEqual(
            last_user_change.endpoint, request.endpoint)
        
        system_logs = db.session.query(SystemLog).order_by(
            SystemLog.id.desc())
        self.assertEqual(system_logs.count(), 2)
        last_log = system_logs.first()
        self.assertEqual(
            last_log.event_code, SystemLogEventCode.UserLogin)
        self.assertEqual(last_log.event_time, cur_time)
        self.assertEqual(
            last_log.event_desc,
            "user {} [{}] logged in".format(
                user.username, user.id))
        self.assertEqual(last_log.referrer, request.referrer)
        self.assertEqual(last_log.user_agent, request.user_agent)
        self.assertEqual(
            last_log.remote_addr, request.headers.get("X-Forwarded-For"))
        self.assertEqual(last_log.endpoint, request.endpoint)

    def test_execute_login_user_doesnt_exist(self):
        """
        Test logging in when user doesn't exist, triggering an error.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
        referrer = "localhost"
        user_agent = "mozkillah 420.69"
        endpoint = "/login"
        remote_addr = "127.0.0.1"
        headers = {
            "X-Forwarded-For": "192.168.0.1"}
        cur_time = datetime.now()

        request = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint=endpoint, remote_addr=remote_addr,
            headers=headers)

        # when
        code = None
        try:
            execute_login(
                username, password, request, cur_time=cur_time)
        except Exception as e:
            self.assertIsInstance(e, LoginError)
            code, msg = e.args

        # then
        self.assertEqual(code, ErrorCode.UserDoesNotExist)
        self.assertEqual(msg, "Access denied!")

    def test_execute_login_password_error(self):
        """
        Test registering then logging in a user with a wrong password
        triggering an error.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
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
            username, password, password, name, email,
            request, cur_time)
        
        request.endpoint = "/login"
        code = None
        try:
            execute_login(
                username, password+"foo", request, cur_time=cur_time)
        except Exception as e:
            self.assertIsInstance(e, LoginError)
            code, msg = e.args

        self.assertEqual(code, ErrorCode.UserPasswordIncorrect)
        self.assertEqual(msg, "Access denied!")

    def test_execute_logout_with_null_current_user(self):
        """
        Test that we get an error when passing a null current user
        """
        # when
        code = None
        try:
            execute_logout(None, None)
        except Exception as e:
            self.assertIsInstance(e, LogoutError)
            code, msg = e.args

        # then
        self.assertEqual(code, ErrorCode.UserNull)
        self.assertEqual(msg, "Null user")

    def test_execute_logout(self):
        """
        Test that calling execute_logout writes the expected
        records to database.
        """
        # with
        username = "root"
        password = "asDf1234#!1"
        name = "admin"
        email = "root@tx.wtf"
        referrer = "localhost"
        user_agent = "mozkillah 420.69"
        endpoint = "/register"
        remote_addr = "127.0.0.1"
        headers = {
            "X-Forwarded-For": "192.168.0.1"}

        request = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint=endpoint, remote_addr=remote_addr,
            headers=headers)
        request_login = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint="/login", remote_addr=remote_addr,
            headers=headers)
        request_logout = FakeRequest(
            referrer=referrer, user_agent=user_agent,
            endpoint="/logout", remote_addr=remote_addr,
            headers=headers)

        # when
        register_user(
            username, password, password, name, email,
            request)
        user = execute_login(username, password, request_login)

        code = None
        cur_time = datetime.now()
        execute_logout(request_logout, user, cur_time)

        # then
        user_changes = db.session.query(UserChange).order_by(
            UserChange.id.desc())
        last_user_change = user_changes.first()
        self.assertEqual(last_user_change.user_id, user.id)
        self.assertEqual(
            last_user_change.change_code,
            UserChangeEventCode.UserLogout)
        self.assertEqual(
            last_user_change.change_time, cur_time)
        self.assertEqual(
            last_user_change.change_desc,
            "logging out from {}".format(headers["X-Forwarded-For"]))
        self.assertEqual(
            last_user_change.referrer, request_logout.referrer)
        self.assertEqual(
            last_user_change.user_agent, request_logout.user_agent)
        self.assertEqual(
            last_user_change.remote_addr,
            request_logout.headers.get("X-Forwarded-For"))
        self.assertEqual(
            last_user_change.endpoint, request_logout.endpoint)
        
        system_logs = db.session.query(SystemLog).order_by(
            SystemLog.id.desc())
        last_log = system_logs.first()
        self.assertEqual(
            last_log.event_code, SystemLogEventCode.UserLogout)
        self.assertEqual(last_log.event_time, cur_time)
        self.assertEqual(
            last_log.event_desc,
            "user {} [{}] logging out".format(
                user.username, user.id))
        self.assertEqual(last_log.referrer, request_logout.referrer)
        self.assertEqual(last_log.user_agent, request_logout.user_agent)
        self.assertEqual(
            last_log.remote_addr,
            request_logout.headers.get("X-Forwarded-For"))
        self.assertEqual(last_log.endpoint, request_logout.endpoint)

if __name__ == '__main__':
    unittest.main()