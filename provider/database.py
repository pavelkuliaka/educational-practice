import sqlite3
from sqlite3 import Connection
from flask import g

from typing import Any


DATABASE = "./provider/users.db"


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
                email TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                nonce TEXT
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
