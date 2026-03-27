import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv("./client/.env")

env = os.environ

required = [
    "APP_SECRET_KEY",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "YANDEX_CLIENT_ID",
    "YANDEX_CLIENT_SECRET",
]

missing = [key for key in required if not env.get(key)]
if missing:
    raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

CONFIGS = {
    "google": {
        "name": "Google",
        "icon": "static/icons/google.svg",
        "client_id": env["GOOGLE_CLIENT_ID"],
        "client_secret": env["GOOGLE_CLIENT_SECRET"],
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "openid email",
        "auth_type": {
            "type": "OIDC",
            "params": {
                "issuer": "https://accounts.google.com",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "algorithms": ["RS256"],
            },
        },
        "token_request_headers": {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    },
    "github": {
        "name": "GitHub",
        "icon": "static/icons/github.svg",
        "client_id": env["GITHUB_CLIENT_ID"],
        "client_secret": env["GITHUB_CLIENT_SECRET"],
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "read:user user:email",
        "auth_type": {
            "type": "OAuth2",
            "params": {
                "user_info_url": "https://api.github.com/user/emails",
                "email_request_headers": lambda access_token: {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            },
        },
        "token_request_headers": {"Accept": "application/json"},
    },
    "yandex": {
        "name": "Яндекс",
        "icon": "static/icons/yandex.svg",
        "client_id": env["YANDEX_CLIENT_ID"],
        "client_secret": env["YANDEX_CLIENT_SECRET"],
        "auth_url": "https://oauth.yandex.ru/authorize",
        "token_url": "https://oauth.yandex.ru/token",
        "scope": "login:email login:info",
        "auth_type": {
            "type": "OAuth2",
            "params": {
                "user_info_url": "https://login.yandex.ru/info",
                "email_request_headers": lambda access_token: {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            },
        },
        "token_request_headers": {"Accept": "application/json"},
    },
}

PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

APP_SECRET_KEY = env["APP_SECRET_KEY"]

DATABASE_PATH = env.get("DATABASE_PATH", "./client/users.db")
