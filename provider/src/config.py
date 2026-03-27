import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv("./provider/.env")

env = os.environ

required = ["APP_SECRET_KEY", "JWT_SECRET"]
missing = [key for key in required if not env.get(key)]
if missing:
    raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

APP_SECRET_KEY = env["APP_SECRET_KEY"]
JWT_SECRET = env["JWT_SECRET"]

# RSA ключи для RS256
RSA_PRIVATE_KEY = env.get("RSA_PRIVATE_KEY")
if RSA_PRIVATE_KEY:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    PRIVATE_KEY = serialization.load_pem_private_key(
        RSA_PRIVATE_KEY.encode(), password=None, backend=default_backend()
    )
    PUBLIC_KEY = PRIVATE_KEY.public_key()
    PUBLIC_KEY_PEM = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
else:
    PRIVATE_KEY = None
    PUBLIC_KEY = None
    PUBLIC_KEY_PEM = ""

# URL эмитента для OpenID Connect
ISSUER_URL = "http://localhost:5001/oauth"

# Время жизни сессии пользователя
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

DATABASE_PATH = env.get("DATABASE_PATH", "./provider/users.db")
