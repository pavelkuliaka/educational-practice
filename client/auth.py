from werkzeug.security import check_password_hash, generate_password_hash
from database import get_database


def verify_user(email, password):
    database = get_database()
    cursor = database.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))

    user = cursor.fetchone()

    if not user:
        return False

    if user["provider"]:
        return user["provider"]

    if check_password_hash(user["password_hash"], password):
        return True

    return False


def register_user(email, password):
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

    if existing_user["provider"]:
        return existing_user["provider"]

    return False
