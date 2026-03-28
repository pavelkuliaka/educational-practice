import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import check_password_hash, generate_password_hash
from database import get_database


def verify_user(email: str | None, password: str | None) -> bool | str:
    if not email or not password:
        return False

    database = get_database()
    cursor = database.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        return False

    provider = user["provider"]
    if provider:
        cursor.close()
        return provider

    result = check_password_hash(user["password_hash"], password)
    cursor.close()
    return result


def register_user(email: str | None, password: str | None) -> bool | str:
    if not email or not password:
        return False

    database = get_database()
    cursor = database.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

    existing_user = cursor.fetchone()

    if not existing_user:
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users 
            (email, password_hash, provider)
            VALUES (?, ?, ?)
            """,
            (email, password_hash, None),
        )

        database.commit()
        cursor.close()
        return True

    provider = existing_user["provider"]
    cursor.close()
    if provider:
        return provider

    return False
