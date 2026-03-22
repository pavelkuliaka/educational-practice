from dotenv import dotenv_values
from datetime import timedelta


env = dotenv_values("./client/.env")

PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

APP_SECRET_KEY = env["APP_SECRET_KEY"]
