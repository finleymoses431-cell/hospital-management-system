import os
from pathlib import Path

from werkzeug.security import generate_password_hash

import database.database as database


database_path = os.getenv("HOSPITAL_DATABASE_PATH")
if database_path:
    database.DATABASE = Path(database_path)
    database.DATABASE.parent.mkdir(parents=True, exist_ok=True)


def create_render_admin():
    username = os.getenv("ADMIN_USERNAME", "admin").strip()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not username or len(password) < 12:
        raise RuntimeError(
            "Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters."
        )

    connection = database.get_connection()
    try:
        existing_admin = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_admin is None:
            connection.execute(
                """
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
                """,
                (username, generate_password_hash(password), "Administrator")
            )
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


database.create_admin = create_render_admin

from app import app
