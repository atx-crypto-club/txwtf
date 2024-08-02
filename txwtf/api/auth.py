import time
from typing import Dict

import jwt
from decouple import config

from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


JWT_SECRET = None
JWT_ALGORITHM = None


def init_config():
    global JWT_SECRET
    global JWT_ALGORITHM
    JWT_SECRET = config("secret") if JWT_SECRET is None else JWT_SECRET
    JWT_ALGORITHM = config("algorithm") if JWT_ALGORITHM is None else JWT_ALGORITHM


def token_response(token: str):
    return {"access_token": token}


def sign_jwt(
    user_id: str,
    jwt_secret: str = None,
    jwt_algorithm: str = None,
    expire_time: float = 600.0,
) -> Dict[str, str]:
    if jwt_secret is None:
        jwt_secret = JWT_SECRET
    if jwt_algorithm is None:
        jwt_algorithm = JWT_ALGORITHM
    payload = {"user_id": user_id, "expires": time.time() + expire_time}
    token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)
    return token_response(token)


def decode_jwt(
    token: str,
    jwt_secret: str = None,
    jwt_algorithm: str = None
) -> dict:
    if jwt_secret is None:
        jwt_secret = JWT_SECRET
    if jwt_algorithm is None:
        jwt_algorithm = JWT_ALGORITHM
    try:
        decoded_token = jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

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
        isTokenValid: bool = False

        try:
            payload = decode_jwt(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True

        return isTokenValid
