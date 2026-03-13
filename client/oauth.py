import secrets
from flask import session, url_for
from config import CONFIGS
import requests
import jwt


def build_auth_url(provider):
    state = secrets.token_urlsafe(32)

    session["oauth_state"] = state

    params = {
        "client_id": CONFIGS[provider]["client_id"],
        "redirect_uri": f"http://localhost:5000/callback/{provider}",
        "response_type": "code",
        "scope": CONFIGS[provider]["scope"],
        "state": state,
    }

    if provider == "google":
        nonce = secrets.token_urlsafe(16)

        session["oauth_nonce"] = nonce

        params["nonce"] = nonce
        params["prompt"] = "consent"

    session.permanent = True

    return f"{CONFIGS[provider]['auth_url']}?{requests.compat.urlencode(params)}"


def get_tokens(provider, code):
    token_data = {
        "code": code,
        "client_id": CONFIGS[provider]["client_id"],
        "client_secret": CONFIGS[provider]["client_secret"],
        "redirect_uri": url_for("callback", provider=provider, _external=True),
        "grant_type": "authorization_code",
    }

    headers = {"Accept": "application/json"}
    if provider == "google":
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    token_response = requests.post(
        CONFIGS[provider]["token_url"], data=token_data, headers=headers
    )

    if token_response.status_code != 200:
        return None

    tokens = token_response.json()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    id_token = tokens.get("id_token")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
    }


def get_email_oauth2(provider, access_token):
    headers = None
    if provider == "github":
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/json",
        }
    elif provider == "yandex":
        headers = {"Authorization": f"OAuth {access_token}"}
    else:
        return None

    user_response = requests.get(CONFIGS[provider]["userinfo_url"], headers=headers)

    if user_response.status_code != 200:
        return None

    user_data = user_response.json()

    email = None

    if provider == "github":
        email = user_data.get("email")
        if not email:
            email_response = requests.get(
                "https://api.github.com/user/emails", headers=headers
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                for email_data in emails:
                    if email_data.get("primary") and email_data.get("verified"):
                        email = email_data.get("email")
                        break
    elif provider == "yandex":
        email = user_data.get("default_email")

    return email


def get_email_oidc(provider, id_token):
    try:
        jwks_client = jwt.PyJWKClient(CONFIGS[provider]["jwks_uri"])
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=[CONFIGS[provider]["algorithm"]],
            audience=CONFIGS[provider]["client_id"],
            issuer=CONFIGS[provider]["issuer"],
            options={"verify_exp": True},
        )

        if payload.get("nonce") != session.get("oauth_nonce"):
            return None

        email = payload.get("email")
        return email

    except jwt.InvalidTokenError:
        return None
