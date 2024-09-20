"""
Tests for the txwtf.api module.
"""
from contextlib import asynccontextmanager
import unittest

from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

import txwtf.core
from txwtf.version import version
from txwtf.api import create_app


@asynccontextmanager
async def get_client(app: FastAPI):
    async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://localhost"
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
        async with LifespanManager(self._app) as manager:
            async with get_client(manager.app) as ac:
                response = await ac.get("/")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.json()["message"],
                    "txwtf v{}".format(version)
                )

    async def test_register(self):
        """"
        Test the user registration endpoint.
        """
        # with
        data = {
            "username": "testuser",
            "password": "passWord1234!@",
            "verify_password": "passWord1234!@",
            "name": "clown",
            "email": "clown@clownz.com"
        }

        # when
        async with LifespanManager(self._app) as manager:
            async with get_client(manager.app) as ac:
                response = await ac.post("/register", json=data)

        # then
        self.assertEqual(response.status_code, 200)

        retval = response.json()
        self.assertEqual(retval["username"], data["username"])
        self.assertEqual(retval["name"], data["name"])
        self.assertEqual(retval["email"], data["email"])


if __name__ == "__main__":
    unittest.main()
