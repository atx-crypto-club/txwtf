"""
Tests for the txwtf.core module.
"""

import asyncio
from datetime import datetime, timedelta
import time
import unittest
import uuid

import email_validator
from werkzeug.security import check_password_hash

from sqlmodel import SQLModel, Session, select

import txwtf.core
from txwtf.core.codes import ErrorCode, SystemLogEventCode
from txwtf.core import (
    sign_jwt,
    decode_jwt,
    authorized_session_launch,
    authorized_sessions,
    authorized_session_deactivate,
    authorized_session_verify,
    hash,
    gen_secret,
    get_setting,
    get_setting_record,
    has_setting,
    list_setting,
    set_setting,
    get_site_logo,
    get_default_avatar,
    get_default_card_image,
    get_default_header_image,
    get_password_lower_enabled,
    get_password_max_length,
    get_password_max_length_enabled,
    get_password_min_length,
    get_password_min_length_enabled,
    get_password_special_symbols,
    get_password_special_symbols_enabled,
    get_password_digit_enabled,
    get_password_upper_enabled,
    get_email_validate_deliverability_enabled,
    password_check,
    register_user,
    execute_login,
    execute_logout,
    get_user,
    get_groups,
)
from txwtf.core.defaults import (
    SITE_LOGO,
    AVATAR,
    CARD_IMAGE,
    HEADER_IMAGE,
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
    DEFAULT_JWT_ALGORITHM,
)
from txwtf.core.errors import (
    TXWTFError,
    SettingsError,
    PasswordError,
    RegistrationError,
    LoginError,
    LogoutError,
    AuthorizedSessionError,
    UserError,
)
from txwtf.core.db import get_engine, init_db, get_session, get_session
from txwtf.core.model import (
    AuthorizedSession,
    GlobalSettings,
    User,
    SystemLog,
)


# Turn off DNS validation for tests
email_validator.TEST_ENVIRONMENT = True


class FakeRequest(object):
    def __init__(self, **kwargs):
        self.referrer = kwargs["referrer"]
        self.user_agent = kwargs["user_agent"]
        self.endpoint = kwargs["endpoint"]
        self.remote_addr = kwargs["remote_addr"]
        self.headers = kwargs["headers"]


class TestCore(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._engine = get_engine("sqlite+aiosqlite://")
        await init_db(self._engine)

        self._jwt_secret = gen_secret()
        self._jwt_algorithm = DEFAULT_JWT_ALGORITHM

    async def asyncTearDown(self):
        async with self._engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.drop_all)

    def test_valid_identifier(self):
        """
        Test valid_identifier
        """
        # with
        good_values = ["b0llocks", "clownworld", "__test", "_test0", "__test__"]
        bad_values = ["1clown", "f00.", "#asdf", r"%fff", r"{ff1...}", "fasd^", ""]

        # when
        gv = [txwtf.core.valid_identifier(val) for val in good_values]
        nbv = [not txwtf.core.valid_identifier(val) for val in bad_values]

        # then
        self.assertTrue(all(gv))
        self.assertTrue(all(nbv))

    async def test_get_setting_default(self):
        """
        Test that get setting returns None when no setting is available.
        """
        async with get_session(self._engine) as session:
            # when
            code = None
            try:
                await get_setting(session, "nothing")
            except TXWTFError as e:
                self.assertIsInstance(e, SettingsError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.SettingDoesntExist)
            self.assertFalse(await has_setting(session, "nothing"))

    async def test_get_setting(self):
        """
        Test that get setting returns what is set.
        """
        async with get_session(self._engine) as session:
            # with
            var = "test_setting"
            val = "value"

            # when
            await set_setting(session, var, val)

            # then
            self.assertEqual(await get_setting(session, var), val)
            self.assertTrue(await has_setting(session, var))

    async def test_get_setting_record_recursive(self):
        """
        Test that we can get child settings.
        """
        async with get_session(self._engine) as session:
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
                accessed_time=now0,
            )
            session.add(setting0)
            await session.commit()
            now1 = datetime.now()
            setting1 = GlobalSettings(
                var=var1,
                val=val1,
                parent_id=setting0.id,
                created_time=now1,
                modified_time=now1,
                accessed_time=now1,
            )
            session.add(setting1)
            await session.commit()

            # then
            self.assertEqual(setting0, await get_setting_record(session, var0))

            code = None
            try:
                await get_setting_record(session, var1)
            except TXWTFError as e:
                self.assertIsInstance(e, SettingsError)
                code, _ = e.args
            self.assertEqual(code, ErrorCode.SettingDoesntExist)
            self.assertEqual(
                setting1,
                await get_setting_record(
                    session,
                    var1,
                    parent_id=setting0.id
                )
            )
            self.assertEqual(setting1, await get_setting_record(session, var0, var1))

    async def test_get_setting_record_recursive_create(self):
        """
        Test that we can get child settings, creating
        records on demand.
        """
        async with get_session(self._engine) as session:
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
                accessed_time=now0,
            )
            session.add(setting0)
            await session.commit()

            # then
            setting1 = await get_setting_record(
                session, var0, var1, create=True, default=val1, now=now0
            )
            self.assertIsNotNone(setting1)
            self.assertEqual(setting1.parent_id, setting0.id)
            self.assertEqual(setting1.val, val1)
            self.assertEqual(setting1.created_time, now0)

    async def test_set_setting_child(self):
        """
        Test that we can get child settings.
        """
        async with get_session(self._engine) as session:
            # with
            var0 = "test_root"
            val0 = "q"
            var1 = "test_nested"
            val1 = "r"

            # when
            await set_setting(session, var0, val0)
            await set_setting(session, var0, var1, val1)

            # then
            self.assertEqual(val0, await get_setting(session, var0))
            self.assertEqual(val1, await get_setting(session, var0, var1))
            self.assertTrue(await has_setting(session, var0, var1))
            # import pdb; pdb.set_trace()
            val = await list_setting(session, var0)
            self.assertEqual(set(val), {var1})
            self.assertEqual(set(await list_setting(session, var0, var1)), set())

    async def test_get_setting_parent_none(self):
        """
        Test verify that parent nodes return none
        """
        async with get_session(self._engine) as session:
            # with
            var0 = "test_root"
            var1 = "test_nested"
            val1 = "r"

            # when
            await set_setting(session, var0, var1, val1)

            # then
            self.assertIsNone(await get_setting(session, var0))
            self.assertEqual(await get_setting(session, var0, var1), val1)
            self.assertTrue(await has_setting(session, var0, var1))

    async def test_get_setting_parent_not_none(self):
        """
        Test verify that parent nodes can return a value
        """
        async with get_session(self._engine) as session:
            # with
            var0 = "test_root"
            val0 = "q"
            var1 = "test_nested"
            val1 = "r"

            # when
            await set_setting(session, var0, var1, val1)
            await set_setting(session, var0, val0)

            # then
            self.assertEqual(await get_setting(session, var0), val0)
            self.assertEqual(await get_setting(session, var0, var1), val1)
            self.assertTrue(await has_setting(session, var0, var1))

    async def test_site_logo(self):
        """
        Test default site logo setting.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(await get_site_logo(session), SITE_LOGO)

    async def test_site_logo_change(self):
        """
        Test changing site logo setting.
        """
        async with get_session(self._engine) as session:
            # with
            site_logo = "test.png"

            # when
            await set_setting(session, "site_logo", site_logo)

            # then
            self.assertEqual(await get_site_logo(session), site_logo)

    async def test_default_avatar(self):
        """
        Test default avatar setting.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(await get_default_avatar(session), AVATAR)

    async def test_default_avatar_change(self):
        """
        Test changing default avatar setting.
        """
        async with get_session(self._engine) as session:
            # with
            avatar = "test.png"

            # when
            await set_setting(session, "default_avatar", avatar)

            # then
            self.assertEqual(await get_default_avatar(session), avatar)

    async def test_default_card_image(self):
        """
        Test default card image setting.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(await get_default_card_image(session), CARD_IMAGE)

    async def test_default_card_image_change(self):
        """
        Test changing card image setting.
        """
        async with get_session(self._engine) as session:
            # with
            default_card = "test.png"

            # when
            await set_setting(session, "default_card", default_card)

            # then
            self.assertEqual(await get_default_card_image(session), default_card)

    async def test_default_header_image(self):
        """
        Test default header image setting.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(await get_default_header_image(session), HEADER_IMAGE)

    async def test_default_header_image_change(self):
        """
        Test changing header image setting.
        """
        async with get_session(self._engine) as session:
            # with
            default_header = "test.png"

            # when
            await set_setting(session, "default_header", default_header)

            # then
            self.assertEqual(await get_default_header_image(session), default_header)

    async def test_password_special_symbols(self):
        """
        Test default password special symbols setting.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_special_symbols(session), PASSWORD_SPECIAL_SYMBOLS
            )

    async def test_password_special_symbols_change(self):
        """
        Test changing password special symbols setting.
        """
        async with get_session(self._engine) as session:
            # with
            special_sym = "$%^&"

            # when
            await set_setting(session, "passwd_special_symbols", special_sym)

            # then
            self.assertEqual(await get_password_special_symbols(session), special_sym)

    async def test_password_min_length(self):
        """
        Test default password minimumm length.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_min_length(session), PASSWORD_MINIMUM_LENGTH
            )

    async def test_password_min_length_change(self):
        """
        Test changing password minimum length setting.
        """
        async with get_session(self._engine) as session:
            # with
            min_length = 10

            # when
            await set_setting(session, "passwd_minimum_length", min_length)

            # then
            self.assertEqual(await get_password_min_length(session), min_length)

    async def test_password_max_length(self):
        """
        Test default password maximum length.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_max_length(session), PASSWORD_MAXIMUM_LENGTH
            )

    async def test_password_max_length_change(self):
        """
        Test changing password maximum length setting.
        """
        async with get_session(self._engine) as session:
            # with
            max_length = 128

            # when
            await set_setting(session, "passwd_maximum_length", max_length)

            # then
            self.assertEqual(await get_password_max_length(session), max_length)

    async def test_password_special_symbols_enabled(self):
        """
        Test default password special symbols enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_special_symbols_enabled(session),
                PASSWORD_SPECIAL_SYMBOLS_ENABLED,
            )

    async def test_password_special_symbols_enabled_change(self):
        """
        Test changing password special symbols enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            special_symbols_enabled = 0

            # when
            await set_setting(
                session, "passwd_special_sym_enabled", special_symbols_enabled
            )

            # then
            self.assertEqual(
                await get_password_special_symbols_enabled(session),
                special_symbols_enabled,
            )

    async def test_password_min_length_enabled(self):
        """
        Test default password min length enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_min_length_enabled(session),
                PASSWORD_MINIMUM_LENGTH_ENABLED,
            )

    async def test_password_min_length_enabled_change(self):
        """
        Test changing password min length enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            min_length_enabled = 0

            # when
            await set_setting(session, "passwd_minimum_len_enabled", min_length_enabled)

            # then
            self.assertEqual(
                await get_password_min_length_enabled(session), min_length_enabled
            )

    async def test_password_max_length_enabled(self):
        """
        Test default password max length enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_max_length_enabled(session),
                PASSWORD_MAXIMUM_LENGTH_ENABLED,
            )

    async def test_password_max_length_enabled_change(self):
        """
        Test changing password max length enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            max_length_enabled = 0

            # when
            await set_setting(session, "passwd_maximum_len_enabled", max_length_enabled)

            # then
            self.assertEqual(
                await get_password_max_length_enabled(session), max_length_enabled
            )

    async def test_password_digit_enabled(self):
        """
        Test default password digit enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_digit_enabled(session), PASSWORD_DIGIT_ENABLED
            )

    async def test_password_digit_enabled_change(self):
        """
        Test changing password digit enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            digit_enabled = 0

            # when
            await set_setting(session, "passwd_digit_enabled", digit_enabled)

            # then
            self.assertEqual(await get_password_digit_enabled(session), digit_enabled)

    async def test_password_upper_enabled(self):
        """
        Test default password upper enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_upper_enabled(session), PASSWORD_UPPER_ENABLED
            )

    async def test_password_uppper_enabled_change(self):
        """
        Test changing password upper enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            upper_enabled = 0

            # when
            await set_setting(session, "passwd_upper_enabled", upper_enabled)

            # then
            self.assertEqual(await get_password_upper_enabled(session), upper_enabled)

    async def test_password_lower_enabled(self):
        """
        Test default password lower enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_password_lower_enabled(session), PASSWORD_LOWER_ENABLED
            )

    async def test_password_lower_enabled_change(self):
        """
        Test changing password lower enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            lower_enabled = 0

            # when
            await set_setting(session, "passwd_lower_enabled", lower_enabled)

            # then
            self.assertEqual(await get_password_lower_enabled(session), lower_enabled)

    async def test_email_validate_deliverability_enabled(self):
        """
        Test default email validate deliverability enabled flag.
        """
        async with get_session(self._engine) as session:
            self.assertEqual(
                await get_email_validate_deliverability_enabled(session),
                EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
            )

    async def test_email_validate_deliverability_enabled_change(self):
        """
        Test email validate deliverability enabled flag setting.
        """
        async with get_session(self._engine) as session:
            # with
            enabled = 0

            # when
            await set_setting(session, "email_validate_deliv_enabled", enabled)

            # then
            self.assertEqual(
                await get_email_validate_deliverability_enabled(session), enabled
            )

    async def test_password_check(self):
        """
        Test that password checking works as expected with default flags.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDf1234#!1"

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_error_min_length(self):
        """
        Test that password checking fails on default min length.
        """
        async with get_session(self._engine) as session:
            # with
            password = "aD1#!1"

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordTooShort)

    async def test_password_check_error_max_length(self):
        """
        Test that password checking fails on default max length.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDf1234#!1"
            await set_setting(session, "passwd_maximum_length", 8)

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordTooLong)

    async def test_password_check_error_missing_digit(self):
        """
        Test that password checking fails on missing digit.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDfFDSA#!!"

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingDigit)

    async def test_password_check_error_missing_upper(self):
        """
        Test that password checking fails on missing upper case character.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asdf1234#!1"

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingUpper)

    async def test_password_check_error_missing_lower(self):
        """
        Test that password checking fails on missing lower case character.
        """
        async with get_session(self._engine) as session:
            # with
            password = "ASDF1234#!1"

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingLower)

    async def test_password_check_error_missing_symbol(self):
        """
        Test that password checking fails on missing symbol.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDf1234131"

            # when
            code = None
            try:
                await password_check(session, password)
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingSymbol)

    async def test_password_check_symbol_disabled(self):
        """
        Test that password checking works with symbol flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDf1234!1"
            await set_setting(session, "passwd_special_sym_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_symbol_disabled_when_empty(self):
        """
        Test that password checking works when no special
        symbols are specified.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDf1234!1"
            await set_setting(session, "passwd_special_symbols", "")

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_min_length_disabled(self):
        """
        Test that password checking works with min length flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "Aa#4!1"
            await set_setting(session, "passwd_minimum_length", 10)
            await set_setting(session, "passwd_minimum_len_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_max_length_disabled(self):
        """
        Test that password checking works with max length flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "Aa#4!1"
            await set_setting(session, "passwd_minimum_length", 1)
            await set_setting(session, "passwd_maximum_length", 4)
            await set_setting(session, "passwd_maximum_len_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_digit_disabled(self):
        """
        Test that password checking works with digit flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asDffdsa#!1"
            await set_setting(session, "passwd_digit_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_upper_disabled(self):
        """
        Test that password checking works with upper flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "asdffdsa#!1"
            await set_setting(session, "passwd_upper_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_password_check_lower_disabled(self):
        """
        Test that password checking works with lower flag disabled.
        """
        async with get_session(self._engine) as session:
            # with
            password = "ASDFFDSA#!1"
            await set_setting(session, "passwd_lower_enabled", 0)

            # when
            success = True
            try:
                await password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    async def test_register_user(self):
        """
        Test registering a user.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session, username, password, password, name, email, request, cur_time
            )

            # then
            ## check user
            user = (await session.exec(select(User))).first()
            self.assertEqual(user.email, email)
            self.assertEqual(user.name, name)
            self.assertTrue(check_password_hash(user.password, password))
            self.assertEqual(user.created_time, cur_time)
            self.assertEqual(user.modified_time, cur_time)
            self.assertEqual(user.avatar_url, await get_default_avatar(session))
            self.assertEqual(user.card_image_url, await get_default_card_image(session))
            self.assertEqual(
                user.header_image_url, await get_default_header_image(session)
            )
            self.assertEqual(user.header_text, name)
            self.assertEqual(user.description, "{} is on the scene".format(name))
            self.assertEqual(user.email_verified, False)
            self.assertEqual(user.is_admin, False)
            self.assertEqual(user.last_login, None)
            self.assertEqual(user.last_login_addr, None)
            self.assertEqual(user.view_count, 0)
            self.assertEqual(user.post_view_count, 0)
            self.assertEqual(user.username, username)
            self.assertEqual(user.post_count, 0)

            ## check logs
            new_change = (await session.exec(select(SystemLog))).first()
            self.assertEqual(new_change.user_id, user.id)
            self.assertEqual(new_change.event_code, SystemLogEventCode.UserCreate)
            self.assertEqual(new_change.event_time, cur_time)
            self.assertEqual(
                new_change.event_desc,
                "creating new user {} [{}]".format(user.username, user.id),
            )
            self.assertEqual(new_change.referrer, request.referrer)
            self.assertEqual(new_change.user_agent, request.user_agent)
            self.assertEqual(
                new_change.remote_addr, request.headers.get("X-Forwarded-For")
            )
            self.assertEqual(new_change.endpoint, request.endpoint)

    async def test_register_email_exists(self):
        """
        Test that there is an error if an email already exists.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )

            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.EmailExists)

    async def test_register_invalid_username(self):
        """
        Test that registration fails if a username isn't a valid identifier
        """
        async with get_session(self._engine) as session:
            # with
            username = "#asdf"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.InvalidIdentifier)

    async def test_register_username_exists(self):
        """
        Test that there is an error if a username already exists.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )

            code = None
            try:
                # change the email to trigger a username error instead
                email = email + ".net"
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.UsernameExists)

    async def test_register_invalid_email(self):
        """
        Test that there is an error if an unallowed test email is used
        for registration.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@localhost"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.InvalidEmail)

    async def test_register_invalid_email_2(self):
        """
        Test that there is an error if a malformed email is used
        for registration.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@localhost .com"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.InvalidEmail)

    async def test_register_password_mismatch(self):
        """
        Test that there is an error if the password and
        verify_password don't match.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password + "foo",
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, RegistrationError)
                code, _ = e.args

            self.assertEqual(code, ErrorCode.PasswordMismatch)

    async def test_register_password_check_fail(self):
        """
        Test that there is an error if the password fails the password
        check.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "password"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await register_user(
                    session,
                    username,
                    password,
                    password,
                    name,
                    email,
                    request,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            self.assertIsNotNone(code)

    async def test_execute_login(self):
        """
        Test registering then loggin in a user.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session, username, password, password, name, email, request, cur_time
            )

            request.endpoint = "/login"
            user, _ = await execute_login(
                session,
                username,
                password,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                cur_time=cur_time,
            )

            # then
            ## check logs
            user_changes = await session.exec(
                select(SystemLog).order_by(SystemLog.id.desc())
            )
            last_changes = user_changes.all()
            self.assertEqual(len(last_changes), 3)
            last_user_change = last_changes[0]
            self.assertEqual(last_user_change.user_id, user.id)
            self.assertEqual(
                last_user_change.event_code, SystemLogEventCode.UserLogin
            )
            self.assertEqual(last_user_change.event_time, cur_time)
            self.assertEqual(
                last_user_change.event_desc,
                "user {} [{}] logged in from {}".format(
                    user.username, user.id,
                    headers["X-Forwarded-For"]),
            )
            self.assertEqual(last_user_change.referrer, request.referrer)
            self.assertEqual(last_user_change.user_agent, request.user_agent)
            self.assertEqual(
                last_user_change.remote_addr, request.headers.get("X-Forwarded-For")
            )
            self.assertEqual(last_user_change.endpoint, request.endpoint)

    async def test_execute_login_user_doesnt_exist(self):
        """
        Test logging in when user doesn't exist, triggering an error.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/login"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await execute_login(
                    session,
                    username,
                    password,
                    self._jwt_secret,
                    self._jwt_algorithm,
                    request,
                    cur_time=cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, LoginError)
                code, msg = e.args

            # then
            self.assertEqual(code, ErrorCode.UserDoesNotExist)
            self.assertEqual(msg, "Access denied!")

    async def test_execute_login_password_error(self):
        """
        Test registering then logging in a user with a wrong password
        triggering an error.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )

            request.endpoint = "/login"
            code = None
            try:
                await execute_login(
                    session,
                    username,
                    password + "foo",
                    self._jwt_secret,
                    self._jwt_algorithm,
                    request,
                    cur_time=cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, LoginError)
                code, msg = e.args

            self.assertEqual(code, ErrorCode.UserPasswordIncorrect)
            self.assertEqual(msg, "Access denied!")

    async def test_execute_logout(self):
        """
        Test that calling execute_logout writes the expected
        records to database.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )
            request_login = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint="/login",
                remote_addr=remote_addr,
                headers=headers,
            )
            request_logout = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint="/logout",
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            await register_user(
                session,
                username,
                password,
                password,
                name, 
                email,
                request
            )

            user, session_payload = await execute_login(
                session,
                username,
                password,
                self._jwt_secret,
                self._jwt_algorithm,
                request_login,
            )

            session_verified = True
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except:
                session_verified = False

            cur_time = datetime.now()
            await execute_logout(
                session,
                session_payload["uuid"],
                self._jwt_secret,
                request_logout,
                user,
                cur_time,
            )

            session_verified_post_logout = True
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except:
                session_verified_post_logout = False

            # then
            self.assertTrue(session_verified)
            self.assertFalse(session_verified_post_logout)

            user_changes = await session.exec(
                select(SystemLog).order_by(SystemLog.id.desc())
            )
            last_user_change = user_changes.all()[1]
            self.assertEqual(last_user_change.user_id, user.id)
            self.assertEqual(
                last_user_change.event_code, SystemLogEventCode.UserLogout
            )
            self.assertEqual(last_user_change.event_time, cur_time)
            self.assertEqual(
                last_user_change.event_desc,
                "user {} [{}] logged out from {}".format(
                    user.username, user.id,
                    headers["X-Forwarded-For"]),
            )
            self.assertEqual(last_user_change.referrer, request_logout.referrer)
            self.assertEqual(last_user_change.user_agent, request_logout.user_agent)
            self.assertEqual(
                last_user_change.remote_addr,
                request_logout.headers.get("X-Forwarded-For"),
            )
            self.assertEqual(last_user_change.endpoint, request_logout.endpoint)

    def test_auth_jwt(self):
        """
        Test signing and decoding a JWT.
        """
        # with
        secret = txwtf.core.gen_secret()
        algo = DEFAULT_JWT_ALGORITHM
        user_id = 42

        # when
        payload = sign_jwt(secret, algo, user_id)
        token = payload["token"]
        payload_decoded = decode_jwt(secret, algo, token)
        del payload["token"]

        # then
        self.assertEqual(payload, payload_decoded)

    def test_auth_jwt_new_secret(self):
        """
        Test signing and decoding a JWT fails when using a new secret.
        """
        # with
        secret = txwtf.core.gen_secret()
        algo = DEFAULT_JWT_ALGORITHM
        user_id = 42

        # when
        payload = sign_jwt(secret, algo, user_id)
        token = payload["token"]
        secret = txwtf.core.gen_secret()  # secret refresh invalidates token
        error = None
        try:
            decode_jwt(secret, algo, token)
        except TXWTFError as e:
            # then
            error = e
            self.assertIsInstance(e, AuthorizedSessionError)
        self.assertIsNotNone(error)

    async def test_authorized_sessions_default(self):
        """
        There should be no authorized sessions on startup.
        """
        async with get_session(self._engine) as session:
            # when
            sess = await authorized_sessions(session)

            # then
            self.assertEqual(len(sess), 0)

    async def test_authorized_session_launch(self):
        """
        Do a spot check of an authorized session launch
        happy path.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username, 
                password, 
                password, 
                name, 
                email, 
                request, 
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            sessions = await authorized_sessions(session)

            # then
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].user_id, user.id)
            self.assertEqual(sessions[0].user_id, session_payload["user_id"])
            self.assertEqual(sessions[0].expires_time, cur_time + expire_delta)
            self.assertEqual(sessions[0].uuid, session_payload["uuid"])
            self.assertEqual(sessions[0].hashed_secret, hash(self._jwt_secret))

            user_changes = await session.exec(
                select(SystemLog).order_by(SystemLog.id.desc())
            )
            last_user_change = user_changes.first()
            self.assertEqual(last_user_change.user_id, user.id)
            self.assertEqual(
                last_user_change.event_code, SystemLogEventCode.LaunchSession
            )
            self.assertEqual(last_user_change.event_time, cur_time)
            self.assertEqual(
                last_user_change.event_desc,
                "launching session {}".format(session_payload["uuid"]),
            )
            self.assertEqual(last_user_change.referrer, request.referrer)
            self.assertEqual(last_user_change.user_agent, request.user_agent)
            self.assertEqual(
                last_user_change.remote_addr, request.headers.get("X-Forwarded-For")
            )
            self.assertEqual(last_user_change.endpoint, request.endpoint)

    async def test_authorized_session_launch_invalid_user(self):
        """
        Try authorizing a session with an invalid user id.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            code = None
            try:
                await authorized_session_launch(
                    session,
                    31337,
                    self._jwt_secret,
                    self._jwt_algorithm,
                    request,
                    expire_delta,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, AuthorizedSessionError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.InvalidUser)

    async def test_authorized_session_launch_disabled_user(self):
        """
        Try authorizing a session with a valid user but one
        that has been disabled.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            user.enabled = False
            await session.commit()

            code = None
            try:
                await authorized_session_launch(
                    session,
                    user.id,
                    self._jwt_secret,
                    self._jwt_algorithm,
                    request,
                    expire_delta,
                    cur_time,
                )
            except TXWTFError as e:
                self.assertIsInstance(e, AuthorizedSessionError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.DisabledUser)

    async def test_authorized_session_verify_fail_unknown_session(self):
        """
        Try verifying a session that is unknown and failing.
        """
        async with get_session(self._engine) as session:
            # when
            code = None
            try:
                await authorized_session_verify(
                    session, str(uuid.uuid4()), self._jwt_secret
                )
            except TXWTFError as e:
                self.assertIsInstance(e, AuthorizedSessionError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.UknownSession)

    async def test_authorized_session_verify(self):
        """
        Do a spot check of an authorized session launch and verify
        happy path.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except TXWTFError as e:
                code, _ = e.args

            self.assertIsNone(code)

    async def test_authorized_session_verify_expiry_fail(self):
        """
        Fail verifying an authorized session that expired.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(seconds=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            await asyncio.sleep(1)
            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except TXWTFError as e:
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.ExpiredSession)

    async def test_authorized_session_verify_secret_mismatch(self):
        """
        Fail verifying an authorized session generated from a
        different secret.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], txwtf.core.gen_secret()
                )
            except TXWTFError as e:
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.InvalidSession)

    async def test_authorized_session_verify_disabled_user(self):
        """
        Fail verifying an authorized session generated from a
        disabled user.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            user.enabled = False
            await session.commit()

            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except TXWTFError as e:
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.DisabledUser)

    async def test_authorized_session_verify_deactivated_session(self):
        """
        Fail verifying an authorized session that has been
        deactivated.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            expire_delta = timedelta(hours=1)
            cur_time = datetime.utcnow()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            request.endpoint = "/login"

            session_payload = await authorized_session_launch(
                session,
                user.id,
                self._jwt_secret,
                self._jwt_algorithm,
                request,
                expire_delta,
                cur_time,
            )

            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except TXWTFError as e:
                code, _ = e.args

            # then
            self.assertIsNone(code)

            request.endpoint = "/logout"
            await authorized_session_deactivate(
                session, session_payload["uuid"], request, cur_time
            )

            code = None
            try:
                await authorized_session_verify(
                    session, session_payload["uuid"], self._jwt_secret
                )
            except TXWTFError as e:
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.DeactivatedSession)

    async def test_get_user(self):
        """
        Test returning a user given a database session and user id.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            test_user = await get_user(session, user.id)

            # then
            self.assertEqual(user, test_user)

    async def test_get_user_from_username(self):
        """
        Test returning a user given a database session and user id.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )

            # then
            self.assertEqual(
                await get_user(session, user_id=user.id),
                await get_user(session, username=user.username))

    async def test_get_user_multiple_users(self):
        """
        Test returning a list of users if we don't provide
        user_id and username.
        """
        async with get_session(self._engine) as session:
            # with
            username = "root"
            password = "asDf1234#!1"
            name = "admin"
            email = "root@tx.wtf"
            referrer = "localhost"
            user_agent = "mozkillah 420.69"
            endpoint = "/register"
            remote_addr = "127.0.0.1"
            headers = {"X-Forwarded-For": "192.168.0.1"}
            cur_time = datetime.now()

            request = FakeRequest(
                referrer=referrer,
                user_agent=user_agent,
                endpoint=endpoint,
                remote_addr=remote_addr,
                headers=headers,
            )

            # when
            user = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )
            username = "root2"
            email = "root2@tx.wtf"
            user2 = await register_user(
                session,
                username,
                password,
                password,
                name,
                email,
                request,
                cur_time
            )

            # then
            users = await get_user(session)
            self.assertIn(user, users, "missing user")
            self.assertIn(user2, users, "missing user")

    async def test_get_user_invalid(self):
        """
        Test that we throw an error if the user id is invalid.
        """
        async with get_session(self._engine) as session:
            # when
            code = None
            try:
                await get_user(session, 420)
            except TXWTFError as e:
                self.assertIsInstance(e, UserError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.InvalidUser)

    async def test_get_groups(self):
        """
        Test for the initial state of groups.
        """
        async with get_session(self._engine) as session:
            # when
            groups = await get_groups(session)

            # then
            # TODO: zero for now- might have more in the future
            # if we start with default groups.
            self.assertEqual(0, len(groups))
            

if __name__ == "__main__":
    unittest.main()
