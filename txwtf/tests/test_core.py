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

    def test_valid_identifier(self):
        """
        Test valid_identifier
        """
        # with
        good_values = [
            "b0llocks", "clownworld", "__test", "_test0", "__test__"]
        bad_values = [
            "1clown", "f00.", "#asdf", r"%fff", r"{ff1...}", "fasd^", ""]
        
        # when
        gv = [txwtf.core.valid_identifier(val) for val in good_values]
        nbv = [not txwtf.core.valid_identifier(val) for val in bad_values]

        # then
        self.assertTrue(all(gv))
        self.assertTrue(all(nbv))
    
