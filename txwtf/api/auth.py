import time
from typing import Dict
import uuid

import jwt
from decouple import config

from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from txwtf.core import gen_secret


DEFAULT_JWT_ALGORITHM = "HS256"


def sign_jwt(
    user_id: str,
    jwt_secret: str,
    jwt_algorithm: str,
    expire_time: float = 600.0,
) -> str:
    payload = {
        "user_id": user_id,
        "expires": time.time() + expire_time,
        "session_id": uuid.uuid4()
    }
    return jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)


def decode_jwt(
    token: str,
    jwt_secret: str,
    jwt_algorithm: str
) -> Dict[str, str]:
    try:
        return jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
    except:
        return {}


class JWTBearer(HTTPBearer):
    def __init__(
        self,
        jwt_secret: str,
        jwt_algorithm: str = DEFAULT_JWT_ALGORITHM,
        auto_error: bool = True,
    ):
        super(JWTBearer, self).__init__(auto_error=auto_error)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        valid: bool = False

        try:
            payload = decode_jwt(jwtoken, self.jwt_secret, self.jwt_algorithm)
            payload = payload if payload["expires"] >= time.time() else None
        except:
            payload = None
        if payload is not None:
            valid = True

        return valid
