import sqlite3
import uuid
from sqlite3 import Connection
from flask import g

from typing import Any

from config import DATABASE_PATH


DATABASE = DATABASE_PATH


def get_database() -> Connection | Any:
    database = getattr(g, "_database", None)

    if database is None:
        database = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
        database.row_factory = sqlite3.Row

    return database


def close_database(exception: Any) -> None:
    database = getattr(g, "_database", None)

    if database is not None:
        database.close()


def init_database() -> None:
    with sqlite3.connect(DATABASE) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                provider TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS apps (
                client_id TEXT PRIMARY KEY,
                client_secret TEXT NOT NULL,
                name TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                nonce TEXT,
                code_challenge TEXT,
                code_challenge_method TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        connection.commit()


def get_user_by_email(email: str) -> dict | None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    return dict(user) if user else None


def create_user(
    email: str, password_hash: str | None = None, provider: str | None = None
) -> str:
    database = get_database()
    cursor = database.cursor()
    user_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO users (user_id, email, password_hash, provider) VALUES (?, ?, ?, ?)",
        (user_id, email, password_hash, provider),
    )
    database.commit()
    return user_id


def get_app_by_client_id(client_id: str) -> dict | None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM apps WHERE client_id = ?", (client_id,))
    app = cursor.fetchone()
    return dict(app) if app else None


def create_app(
    client_id: str, client_secret: str, name: str, redirect_uri: str, owner_email: str
) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "INSERT INTO apps (client_id, client_secret, name, redirect_uri, owner_email) VALUES (?, ?, ?, ?, ?)",
        (client_id, client_secret, name, redirect_uri, owner_email),
    )
    database.commit()


def delete_app(client_id: str, owner_email: str) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "DELETE FROM apps WHERE client_id = ? AND owner_email = ?",
        (client_id, owner_email),
    )
    database.commit()


def update_app_secret(client_id: str, new_secret: str, owner_email: str) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "UPDATE apps SET client_secret = ? WHERE client_id = ? AND owner_email = ?",
        (new_secret, client_id, owner_email),
    )
    database.commit()


def get_apps_by_owner(owner_email: str) -> list[dict]:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM apps WHERE owner_email = ?", (owner_email,))
    apps = cursor.fetchall()
    return [dict(app) for app in apps]


def create_auth_code(
    code: str,
    client_id: str,
    user_id: str,
    email: str,
    expires_at: str,
    nonce: str | None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "INSERT INTO auth_codes (code, client_id, user_id, email, expires_at, nonce, code_challenge, code_challenge_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            code,
            client_id,
            user_id,
            email,
            expires_at,
            nonce,
            code_challenge,
            code_challenge_method,
        ),
    )
    database.commit()


def get_auth_code(code: str) -> dict | None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM auth_codes WHERE code = ?", (code,))
    db_code = cursor.fetchone()
    return dict(db_code) if db_code else None


def delete_auth_code(code: str) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    database.commit()


def create_access_token(token: str, email: str, expires_at: str) -> None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute(
        "INSERT INTO access_tokens (token, email, expires_at) VALUES (?, ?, ?)",
        (token, email, expires_at),
    )
    database.commit()


def get_access_token(token: str) -> dict | None:
    database = get_database()
    cursor = database.cursor()
    cursor.execute("SELECT * FROM access_tokens WHERE token = ?", (token,))
    token_data = cursor.fetchone()
    return dict(token_data) if token_data else None
