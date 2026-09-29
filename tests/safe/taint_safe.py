"""Safe counterpart of taint_vulnerable.py: untrusted data never reaches a dangerous sink."""
import ast
import subprocess
import sys

from flask import request


def run_command():
    path = input("Directory: ")
    subprocess.run(["ls", "--", path], check=False)


def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], check=False)


def get_user(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def calculate():
    return ast.literal_eval(sys.argv[1])
