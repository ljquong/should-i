import os
from collections.abc import Generator

import mysql.connector
from mysql.connector import MySQLConnection


def get_db() -> Generator[MySQLConnection, None, None]:
    connection = mysql.connector.connect(
        host="localhost 2",
        user="root",
        password="Punar_19",
        database="should_i",
    )
    try:
        yield connection
    finally:
        connection.close()
