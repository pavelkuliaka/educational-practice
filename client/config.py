from dotenv import dotenv_values
from datetime import timedelta


env = dotenv_values("./client/.env")

CONFIGS = {
    "my_service": {
        "name": "Мой сервис",
        "client_id": env["MY_SERVICE_CLIENT_ID"],
        "client_secret": env["MY_SERVICE_CLIENT_SECRET"],
        "auth_url": "http://localhost:8001/oauth2/authorize",
        "token_url": "http://localhost:8001/oauth2/access_token",
        "issuer": "",
        "jwks_uri": "",
        "algorithm": "",
        "scope": "",
    },
    "google": {
        "name": "Google",
        "client_id": env["GOOGLE_CLIENT_ID"],
        "client_secret": env["GOOGLE_CLIENT_SECRET"],
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "issuer": "https://accounts.google.com",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "algorithm": "RS256",
        "scope": "openid email",
    },
    "github": {
        "name": "GitHub",
        "client_id": env["GITHUB_CLIENT_ID"],
        "client_secret": env["GITHUB_CLIENT_SECRET"],
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
    "yandex": {
        "name": "Яндекс",
        "client_id": env["YANDEX_CLIENT_ID"],
        "client_secret": env["YANDEX_CLIENT_SECRET"],
        "auth_url": "https://oauth.yandex.ru/authorize",
        "token_url": "https://oauth.yandex.ru/token",
        "userinfo_url": "https://login.yandex.ru/info",
        "scope": "login:email login:info",
    },
}

PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

APP_SECRET_KEY = env["APP_SECRET_KEY"]
