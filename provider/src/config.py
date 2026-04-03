import os
from dotenv import load_dotenv
from datetime import timedelta
from crypto import load_rsa_private_key

load_dotenv("./provider/.env")

env = os.environ

required = ["APP_SECRET_KEY"]
missing = [key for key in required if not env.get(key)]
if missing:
    raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

APP_SECRET_KEY = env["APP_SECRET_KEY"]

RSA_PRIVATE_KEY = env.get("RSA_PRIVATE_KEY")
if RSA_PRIVATE_KEY:
    PRIVATE_KEY = load_rsa_private_key(RSA_PRIVATE_KEY)
else:
    PRIVATE_KEY = None

ISSUER_URL = env.get("ISSUER_URL", "http://localhost:5001/oauth")

PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

DATABASE_PATH = env.get("DATABASE_PATH", "./provider/users.db")
