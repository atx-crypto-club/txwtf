"""
Tests for the txwtf.api module.
"""
import os
import tempfile
import unittest

from sqlmodel import SQLModel, Session

from txwtf.api.core import (
    ErrorCode, get_setting, has_setting, set_setting, SettingsError
)
from txwtf.api.db import get_engine


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

