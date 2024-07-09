import unittest

from flask_testing import TestCase

from txwtf.webapp import create_app, db
from txwtf.webapp.utils import (
    get_setting, set_setting, get_site_logo,
    get_default_card_image, get_default_header_image,
    DEFAULT_SITE_LOGO, DEFAULT_CARD_IMAGE,
    DEFAULT_HEADER_IMAGE)


class TestWebappUtils(TestCase):

    SQLALCHEMY_DATABASE_URI = "sqlite://"
    TESTING = True

    def create_app(self):
        return create_app()

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

    def test_default_site_logo(self):
        """
        Test default site logo setting.
        """
        self.assertEqual(get_site_logo(), DEFAULT_SITE_LOGO)

    def test_default_card_image(self):
        """
        Test default card image setting.
        """
        self.assertEqual(get_default_card_image(), DEFAULT_CARD_IMAGE)

    def test_default_header_image(self):
        """
        Test default header image setting.
        """
        self.assertEqual(get_default_header_image(), DEFAULT_HEADER_IMAGE)


if __name__ == '__main__':
    unittest.main()