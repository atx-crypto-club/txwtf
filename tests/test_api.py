"""
Tests for the txwtf.api module.
"""
from datetime import datetime
import unittest

from sqlmodel import SQLModel, Session

from txwtf.api.core import (
    ErrorCode, 
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
    SITE_LOGO,
    AVATAR,
    CARD_IMAGE,
    HEADER_IMAGE,
    PASSWORD_SPECIAL_SYMBOLS, PASSWORD_MINIMUM_LENGTH,
    PASSWORD_MAXIMUM_LENGTH, PASSWORD_SPECIAL_SYMBOLS_ENABLED,
    PASSWORD_MINIMUM_LENGTH_ENABLED,
    PASSWORD_MAXIMUM_LENGTH_ENABLED,
    PASSWORD_DIGIT_ENABLED, PASSWORD_UPPER_ENABLED,
    PASSWORD_LOWER_ENABLED,
    EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
    SettingsError, PasswordError
)
from txwtf.api.db import get_engine
from txwtf.api.model import GlobalSettings


class TestAPI(unittest.TestCase):
    def setUp(self):
        self._engine = get_engine("sqlite://")
        SQLModel.metadata.create_all(self._engine)

    def tearDown(self):
        SQLModel.metadata.drop_all(self._engine)

    def test_get_setting_default(self):
        """
        Test that get setting returns None when no setting is available.
        """
        with Session(self._engine) as session:
            # when
            code = None
            try:
                get_setting(session, "nothing")
            except Exception as e:
                self.assertIsInstance(e, SettingsError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.SettingDoesntExist)
            self.assertFalse(has_setting(session, "nothing"))

    def test_get_setting(self):
        """
        Test that get setting returns what is set.
        """
        with Session(self._engine) as session:
            # with
            var = "test_setting"
            val = "value"

            # when
            set_setting(session, var, val)

            # then
            self.assertEqual(get_setting(session, var), val)
            self.assertTrue(has_setting(session, var))

    def test_get_setting_record_recursive(self):
        """
        Test that we can get child settings.
        """
        with Session(self._engine) as session:
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
            session.commit()
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
            session.commit()

            # then
            self.assertEqual(setting0, get_setting_record(session, var0))

            code = None
            try:
                get_setting_record(session, var1)
            except Exception as e:
                self.assertIsInstance(e, SettingsError)
                code, _ = e.args
            self.assertEqual(code, ErrorCode.SettingDoesntExist)
            self.assertEqual(setting1, get_setting_record(session, var1, parent_id=setting0.id))
            self.assertEqual(setting1, get_setting_record(session, var0, var1))


    def test_get_setting_record_recursive_create(self):
        """
        Test that we can get child settings, creating
        records on demand.
        """
        with Session(self._engine) as session:
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
            session.commit()

            # then
            setting1 = get_setting_record(
                session, var0, var1, create=True, default=val1, now=now0)
            self.assertIsNotNone(setting1)
            self.assertEqual(setting1.parent_id, setting0.id)
            self.assertEqual(setting1.val, val1)
            self.assertEqual(setting1.created_time, now0)

    def test_set_setting_child(self):
        """
        Test that we can get child settings.
        """
        with Session(self._engine) as session:
            # with
            var0 = "test_root"
            val0 = "q"
            var1 = "test_nested"
            val1 = "r"

            # when
            set_setting(session, var0, val0)
            set_setting(session, var0, var1, val1)

            # then
            self.assertEqual(val0, get_setting(session, var0))
            self.assertEqual(val1, get_setting(session, var0, var1))
            self.assertTrue(has_setting(session, var0, var1))
            self.assertEqual(set(list_setting(session, var0)), {var1})
            self.assertEqual(set(list_setting(session, var0, var1)), set())

    def test_get_setting_parent_none(self):
        """
        Test verify that parent nodes return none
        """
        with Session(self._engine) as session:
            # with
            var0 = "test_root"
            var1 = "test_nested"
            val1 = "r"

            # when
            set_setting(session, var0, var1, val1)

            # then
            self.assertIsNone(get_setting(session, var0))
            self.assertEqual(get_setting(session, var0, var1), val1)
            self.assertTrue(has_setting(session, var0, var1))

    def test_get_setting_parent_not_none(self):
        """
        Test verify that parent nodes can return a value
        """
        with Session(self._engine) as session:
            # with
            var0 = "test_root"
            val0 = "q"
            var1 = "test_nested"
            val1 = "r"

            # when
            set_setting(session, var0, var1, val1)
            set_setting(session, var0, val0)

            # then
            self.assertEqual(get_setting(session, var0), val0)
            self.assertEqual(get_setting(session, var0, var1), val1)
            self.assertTrue(has_setting(session, var0, var1))

    def test_site_logo(self):
        """
        Test default site logo setting.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_site_logo(session), SITE_LOGO)

    def test_site_logo_change(self):
        """
        Test changing site logo setting.
        """
        with Session(self._engine) as session:
            # with
            site_logo = "test.png"

            # when
            set_setting(session, "site_logo", site_logo)

            # then
            self.assertEqual(get_site_logo(session), site_logo)

    def test_default_avatar(self):
        """
        Test default avatar setting.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_default_avatar(session), AVATAR)

    def test_default_avatar_change(self):
        """
        Test changing default avatar setting.
        """
        with Session(self._engine) as session:
            # with
            avatar = "test.png"

            # when
            set_setting(session, "default_avatar", avatar)

            # then
            self.assertEqual(get_default_avatar(session), avatar)

    def test_default_card_image(self):
        """
        Test default card image setting.
        """
        with Session(self._engine) as session:
            self.assertEqual(
                get_default_card_image(session), CARD_IMAGE)

    def test_default_card_image_change(self):
        """
        Test changing card image setting.
        """
        with Session(self._engine) as session:
            # with
            default_card = "test.png"

            # when
            set_setting(session, "default_card", default_card)

            # then
            self.assertEqual(get_default_card_image(session), default_card)

    def test_default_header_image(self):
        """
        Test default header image setting.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_default_header_image(session), HEADER_IMAGE)

    def test_default_header_image_change(self):
        """
        Test changing header image setting.
        """
        with Session(self._engine) as session:
            # with
            default_header = "test.png"

            # when
            set_setting(session, "default_header", default_header)

            # then
            self.assertEqual(get_default_header_image(session), default_header)

    def test_password_special_symbols(self):
        """
        Test default password special symbols setting.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_special_symbols(session), PASSWORD_SPECIAL_SYMBOLS)

    def test_password_special_symbols_change(self):
        """
        Test changing password special symbols setting.
        """
        with Session(self._engine) as session:
            # with
            special_sym = "$%^&"

            # when
            set_setting(session, "password_special_symbols", special_sym)

            # then
            self.assertEqual(get_password_special_symbols(session), special_sym)

    def test_password_min_length(self):
        """
        Test default password minimumm length.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_min_length(session), PASSWORD_MINIMUM_LENGTH)

    def test_password_min_length_change(self):
        """
        Test changing password minimum length setting.
        """
        with Session(self._engine) as session:
            # with
            min_length = 10

            # when
            set_setting(session, "password_minimum_length", min_length)

            # then
            self.assertEqual(get_password_min_length(session), min_length)

    def test_password_max_length(self):
        """
        Test default password maximum length.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_max_length(session), PASSWORD_MAXIMUM_LENGTH)

    def test_password_max_length_change(self):
        """
        Test changing password maximum length setting.
        """
        with Session(self._engine) as session:
            # with
            max_length = 128

            # when
            set_setting(session, "password_maximum_length", max_length)

            # then
            self.assertEqual(get_password_max_length(session), max_length)

    def test_password_special_symbols_enabled(self):
        """
        Test default password special symbols enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(
                get_password_special_symbols_enabled(session), PASSWORD_SPECIAL_SYMBOLS_ENABLED
            )

    def test_password_special_symbols_enabled_change(self):
        """
        Test changing password special symbols enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            special_symbols_enabled = 0

            # when
            set_setting(session, "password_special_symbols_enabled", special_symbols_enabled)

            # then
            self.assertEqual(
                get_password_special_symbols_enabled(session), special_symbols_enabled
            )

    def test_password_min_length_enabled(self):
        """
        Test default password min length enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(
                get_password_min_length_enabled(session), PASSWORD_MINIMUM_LENGTH_ENABLED
            )

    def test_password_min_length_enabled_change(self):
        """
        Test changing password min length enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            min_length_enabled = 0

            # when
            set_setting(session, "password_minimum_length_enabled", min_length_enabled)

            # then
            self.assertEqual(get_password_min_length_enabled(session), min_length_enabled)

    def test_password_max_length_enabled(self):
        """
        Test default password max length enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(
                get_password_max_length_enabled(session), PASSWORD_MAXIMUM_LENGTH_ENABLED
            )

    def test_password_max_length_enabled_change(self):
        """
        Test changing password max length enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            max_length_enabled = 0

            # when
            set_setting(session, "password_maximum_length_enabled", max_length_enabled)

            # then
            self.assertEqual(get_password_max_length_enabled(session), max_length_enabled)

    def test_password_digit_enabled(self):
        """
        Test default password digit enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_digit_enabled(session), PASSWORD_DIGIT_ENABLED)

    def test_password_digit_enabled_change(self):
        """
        Test changing password digit enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            digit_enabled = 0

            # when
            set_setting(session, "password_digit_enabled", digit_enabled)

            # then
            self.assertEqual(get_password_digit_enabled(session), digit_enabled)

    def test_password_upper_enabled(self):
        """
        Test default password upper enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_upper_enabled(session), PASSWORD_UPPER_ENABLED)

    def test_password_uppper_enabled_change(self):
        """
        Test changing password upper enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            upper_enabled = 0

            # when
            set_setting(session, "password_upper_enabled", upper_enabled)

            # then
            self.assertEqual(get_password_upper_enabled(session), upper_enabled)

    def test_password_lower_enabled(self):
        """
        Test default password lower enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(get_password_lower_enabled(session), PASSWORD_LOWER_ENABLED)

    def test_password_lower_enabled_change(self):
        """
        Test changing password lower enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            lower_enabled = 0

            # when
            set_setting(session, "password_lower_enabled", lower_enabled)

            # then
            self.assertEqual(get_password_lower_enabled(session), lower_enabled)

    def test_email_validate_deliverability_enabled(self):
        """
        Test default email validate deliverability enabled flag.
        """
        with Session(self._engine) as session:
            self.assertEqual(
                get_email_validate_deliverability_enabled(session),
                EMAIL_VALIDATE_DELIVERABILITY_ENABLED,
            )

    def test_email_validate_deliverability_enabled_change(self):
        """
        Test email validate deliverability enabled flag setting.
        """
        with Session(self._engine) as session:
            # with
            enabled = 0

            # when
            set_setting(session, "email_validate_deliverability_enabled", enabled)

            # then
            self.assertEqual(get_email_validate_deliverability_enabled(session), enabled)

    def test_password_check(self):
        """
        Test that password checking works as expected with default flags.
        """
        with Session(self._engine) as session:
            # with
            password = "asDf1234#!1"

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_error_min_length(self):
        """
        Test that password checking fails on default min length.
        """
        with Session(self._engine) as session:
            # with
            password = "aD1#!1"

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordTooShort)

    def test_password_check_error_max_length(self):
        """
        Test that password checking fails on default max length.
        """
        with Session(self._engine) as session:
            # with
            password = "asDf1234#!1"
            set_setting(session, "password_maximum_length", 8)

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordTooLong)

    def test_password_check_error_missing_digit(self):
        """
        Test that password checking fails on missing digit.
        """
        with Session(self._engine) as session:
            # with
            password = "asDfFDSA#!!"

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingDigit)

    def test_password_check_error_missing_upper(self):
        """
        Test that password checking fails on missing upper case character.
        """
        with Session(self._engine) as session:
            # with
            password = "asdf1234#!1"

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingUpper)

    def test_password_check_error_missing_lower(self):
        """
        Test that password checking fails on missing lower case character.
        """
        with Session(self._engine) as session:
            # with
            password = "ASDF1234#!1"

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingLower)

    def test_password_check_error_missing_symbol(self):
        """
        Test that password checking fails on missing symbol.
        """
        with Session(self._engine) as session:
            # with
            password = "asDf1234131"

            # when
            code = None
            try:
                password_check(session, password)
            except Exception as e:
                self.assertIsInstance(e, PasswordError)
                code, _ = e.args

            # then
            self.assertEqual(code, ErrorCode.PasswordMissingSymbol)

    def test_password_check_symbol_disabled(self):
        """
        Test that password checking works with symbol flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "asDf1234!1"
            set_setting(session, "password_special_symbols_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_symbol_disabled_when_empty(self):
        """
        Test that password checking works when no special
        symbols are specified.
        """
        with Session(self._engine) as session:
            # with
            password = "asDf1234!1"
            set_setting(session, "password_special_symbols", "")

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_min_length_disabled(self):
        """
        Test that password checking works with min length flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "Aa#4!1"
            set_setting(session, "password_minimum_length", 10)
            set_setting(session, "password_minimum_length_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_max_length_disabled(self):
        """
        Test that password checking works with max length flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "Aa#4!1"
            set_setting(session, "password_minimum_length", 1)
            set_setting(session, "password_maximum_length", 4)
            set_setting(session, "password_maximum_length_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_digit_disabled(self):
        """
        Test that password checking works with digit flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "asDffdsa#!1"
            set_setting(session, "password_digit_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_upper_disabled(self):
        """
        Test that password checking works with upper flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "asdffdsa#!1"
            set_setting(session, "password_upper_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)

    def test_password_check_lower_disabled(self):
        """
        Test that password checking works with lower flag disabled.
        """
        with Session(self._engine) as session:
            # with
            password = "ASDFFDSA#!1"
            set_setting(session, "password_lower_enabled", 0)

            # when
            success = True
            try:
                password_check(session, password)
            except:
                success = False

            # then
            self.assertTrue(success)