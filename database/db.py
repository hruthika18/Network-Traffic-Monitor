import sqlite3
from pathlib import Path

from config import DATABASE_PATH


def initialize_database():
    """Create the database and required tables."""

    database_folder = Path(DATABASE_PATH).parent
    database_folder.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    schema_path = Path(__file__).parent / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as file:
        schema = file.read()

    connection.executescript(schema)
    connection.commit()
    connection.close()


def get_connection():
    """Create and return a SQLite database connection."""

    return sqlite3.connect(DATABASE_PATH)