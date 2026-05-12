import os
from datetime import timedelta

from crypto import RSAPrivateKey, load_rsa_private_key
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

env = os.environ

required = ["APP_SECRET_KEY"]
missing = [key for key in required if not env.get(key)]
if missing:
    raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

APP_SECRET_KEY: str = env["APP_SECRET_KEY"]

private_key_path: str = env.get("PRIVATE_KEY_PATH", "private_key.pem")
if not os.path.isabs(private_key_path):
    private_key_path = os.path.join(os.path.dirname(__file__), "..", private_key_path)

if not os.path.exists(private_key_path):
    raise FileNotFoundError(
        f"RSA private key not found at {private_key_path}. "
        f"Generate one with: openssl genrsa -out {private_key_path} 2048"
    )

with open(private_key_path) as f:
    PRIVATE_KEY: RSAPrivateKey = load_rsa_private_key(f.read())

ISSUER_URL: str = env.get("ISSUER_URL", "http://localhost:5001/oauth")

PERMANENT_SESSION_LIFETIME: timedelta = timedelta(minutes=30)

database_path: str = env.get("DATABASE_PATH", "users.db")
if not os.path.isabs(database_path):
    database_path = os.path.join(os.path.dirname(__file__), "..", database_path)
DATABASE_PATH: str = database_path
