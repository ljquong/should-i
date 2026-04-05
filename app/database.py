import os
from collections.abc import Generator

import mysql.connector
from mysql.connector import MySQLConnection


def get_db() -> Generator[MySQLConnection, None, None]:
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "should_i"),
    )
    try:
        yield connection
    finally:
        connection.close()
