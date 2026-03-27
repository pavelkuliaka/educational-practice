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
        return False

    provider = user["provider"]
    if provider:
        return provider

    if check_password_hash(user["password_hash"], password):
        return True

    return False


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

        return True

    provider = existing_user["provider"]
    if provider:
        return provider

    return False
