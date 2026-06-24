import subprocess
import sqlite3

def run(cmd):
    # CWE-78: OS command injection
    return subprocess.call(cmd, shell=True)

def lookup(db, user_input):
    # CWE-89: SQL injection
    cur = sqlite3.connect(db).cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
    return cur.fetchall()
