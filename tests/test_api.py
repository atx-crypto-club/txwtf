"""
Tests for the txwtf.api module.
"""
from contextlib import asynccontextmanager
import unittest

from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

import txwtf.core
from txwtf.version import version
from txwtf.api import create_app


@asynccontextmanager
async def get_client(app: FastAPI):
    async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test"
        ) as ac:
        yield ac


class TestAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._app = create_app()

    async def asyncTearDown(self):
        pass

    async def test_root(self):
        """"
        Test the default endpoint
        """
        async with get_client(self._app) as ac:
            response = await ac.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json()["message"],
                "txwtf v{}".format(version)
            )


if __name__ == "__main__":
    unittest.main()
