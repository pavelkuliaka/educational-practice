from dotenv import dotenv_values
from datetime import timedelta


env = dotenv_values("./provider/.env")

# Секретный ключ для подписи сессий Flask
APP_SECRET_KEY = env.get("APP_SECRET_KEY")
if not APP_SECRET_KEY:
    raise ValueError("Cofiguration file error: APP_SECRET_KEY missed")

# Секретный ключ для подписи JWT токенов (ID Token)
JWT_SECRET = env.get("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("Cofiguration file error: APP_SECRET_KEY missed")

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
