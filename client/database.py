import sqlite3
from flask import g


DATABASE = "./client/users.db"


def get_database():
    database = getattr(g, "_database", None)

    if database is None:
        database = g._database = sqlite3.connect(DATABASE)
        database.row_factory = sqlite3.Row

    return database


def close_database(exception):
    database = getattr(g, "_database", None)

    if database is not None:
        database.close()


def init_database():
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
