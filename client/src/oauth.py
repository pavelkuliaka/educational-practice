import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets
from urllib.parse import urlencode
from flask import session, url_for, abort
import requests
import jwt
from utils import extract_email
from config import REDIRECT_URI


def build_auth_url(
    provider: str, client_id: str, scope: str, auth_type_value: str, auth_url: str
) -> str:
    state = secrets.token_urlsafe(32)

    session["oauth2_state"] = state

    params = {
        "client_id": client_id,
        "redirect_uri": f"{REDIRECT_URI}/callback/{provider}",
        "response_type": "code",
        "scope": scope,
        "state": state,
        "prompt": "consent",
    }

    if auth_type_value == "OIDC":
        nonce = secrets.token_urlsafe(16)

        session["oauth2_nonce"] = nonce

        params["nonce"] = nonce

    session.permanent = True

    return f"{auth_url}?{urlencode(params)}"


def get_tokens(
    provider: str,
    code: str,
    client_id: str,
    client_secret: str,
    token_url: str,
    token_request_headers: dict,
) -> dict:
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": url_for("callback", provider=provider, _external=True),
        "grant_type": "authorization_code",
    }

    token_response = requests.post(token_url, token_data, headers=token_request_headers)

    if token_response.status_code != 200:
        abort(400, description="Invalid status code")

    tokens = token_response.json()

    access_token = tokens.get("access_token", None)
    id_token = tokens.get("id_token", None)

    return {"access_token": access_token, "id_token": id_token}


def get_email_OIDC(
    id_token: str, jwks_uri: str, algorithms: list, client_id: str, issuer: str
) -> str:
    try:
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms,
            audience=client_id,
            issuer=issuer,
            options={"verify_exp": True},
        )

        if payload.get("nonce", None) != session.get("oauth2_nonce", None):
            session.pop("oauth2_nonce", None)
            abort(400, description="Invalid NONCE")

        email = payload.get("email", None)
        session.pop("oauth2_state", None)
        session.pop("oauth2_nonce", None)
        return email

    except jwt.InvalidTokenError:
        session.pop("oauth2_nonce", None)
        abort(400, description="Invalid ID token")


def get_email_OAuth2(user_info_url: str, headers: dict) -> str:
    user_response = requests.get(url=user_info_url, headers=headers)

    if user_response.status_code != 200:
        abort(400, description="Invalid status code")

    user_data = user_response.json()

    email = extract_email(user_data)

    return email
