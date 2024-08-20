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
    SITE_LOGO,
    AVATAR,
    CARD_IMAGE,
    HEADER_IMAGE,
    SettingsError
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
