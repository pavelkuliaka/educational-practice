import sqlite3
from sqlite3 import Connection
from flask import g

from typing import Any


DATABASE = "./client/users.db"


def get_database() -> Connection | Any:
    database = getattr(g, "_database", None)

    if database is None:
        database = g._database = sqlite3.connect(DATABASE)
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

        connection.commit()
        