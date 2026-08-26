"""Vulnerable: user input flows unsanitized into a SQL query (CWE-89)."""

import sqlite3


def get_user(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    username = input("Username: ")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
