"""
Tests for the txwtf.api module.
"""

import unittest

from httpx import ASGITransport, AsyncClient

import txwtf.core
from txwtf.version import version
from txwtf.api import create_app


class TestAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._app = create_app()

    async def asyncTearDown(self):
        pass

    async def test_root(self):
        """"
        Test the default endpoint
        """
        async with AsyncClient(
            transport=ASGITransport(app=self._app), base_url="http://test"
        ) as ac:
            response = await ac.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["message"], "txwtf v{}".format(version))


if __name__ == "__main__":
    unittest.main()
