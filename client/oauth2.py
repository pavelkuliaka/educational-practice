import secrets
from flask import session, url_for, abort
from config import CONFIGS
import requests
import jwt
from utils import extract_email


def build_auth_url(provider, client_id, scope, auth_type_value):
    state = secrets.token_urlsafe(32)

    session["oauth2_state"] = state

    params = {
        "client_id": client_id,
        "redirect_uri": f"http://localhost:5000/callback/{provider}",
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

    return f"{CONFIGS[provider]['auth_url']}?{requests.compat.urlencode(params)}"


def get_tokens(
    provider, code, client_id, client_secret, token_url, token_request_headers
):
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": url_for("callback", provider=provider, _external=True),
        "grant_type": "authorization_code",
    }

    token_response = requests.post(
        token_url, data=token_data, headers=token_request_headers
    )

    if token_response.status_code != 200:
        abort(400, description="Invalid status code")

    tokens = token_response.json()

    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")

    return {"access_token": access_token, "id_token": id_token}


def get_email_OIDC(id_token, jwks_uri, algorithms, client_id, issuer):
    try:
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=algorithms,
            audience=client_id,
            issuer=issuer,
            options={"verify_exp": True},
        )

        if payload.get("nonce") != session.get("oauth2_nonce"):
            session.pop("oauth2_nonce", None)
            abort(400, description="Invalid NONCE")

        email = payload.get("email")
        session.pop("oauth2_state", None)
        session.pop("oauth2_nonce", None)
        return email

    except jwt.InvalidTokenError:
        session.pop("oauth2_nonce", None)
        abort(400, description="Invalid ID token")


def get_email_OAuth2(user_info_url, headers):
    user_response = requests.get(user_info_url, headers=headers)

    if user_response.status_code != 200:
        abort(400, description="Invalid status code")

    user_data = user_response.json()

    email = extract_email(user_data)

    return email
