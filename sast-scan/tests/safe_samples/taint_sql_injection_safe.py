"""Safe: user input is passed as bound parameters, never concatenated into SQL."""

import sqlite3


def get_user(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    username = input("Username: ")
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
