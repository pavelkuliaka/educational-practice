import os
from dotenv import load_dotenv
from datetime import timedelta
from crypto import load_rsa_private_key

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

env = os.environ

required = ["APP_SECRET_KEY"]
missing = [key for key in required if not env.get(key)]
if missing:
    raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

APP_SECRET_KEY = env["APP_SECRET_KEY"]

private_key_path = env.get("PRIVATE_KEY_PATH", "private_key.pem")
if not os.path.isabs(private_key_path):
    private_key_path = os.path.join(os.path.dirname(__file__), "..", private_key_path)

if os.path.exists(private_key_path):
    with open(private_key_path, "r") as f:
        PRIVATE_KEY = load_rsa_private_key(f.read())
else:
    PRIVATE_KEY = None

ISSUER_URL = env.get("ISSUER_URL", "http://localhost:5001/oauth")

PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

database_path = env.get("DATABASE_PATH", "users.db")
if not os.path.isabs(database_path):
    database_path = os.path.join(os.path.dirname(__file__), "..", database_path)
DATABASE_PATH = database_path
