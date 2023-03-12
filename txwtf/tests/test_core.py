"""
Tests for the txwtf.core module.
"""
import os
import tempfile
import unittest

import txwtf.core


class TestCore(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            self._tmpfile = f.name

    def tearDown(self):
        os.remove(self._tmpfile)

    def test_core_stub(self):
        """
        Test that our boilerplate works.
        """
        # with
        pass

        # when
        val = txwtf.core.stub()

        # then
        self.assertTrue(val)
