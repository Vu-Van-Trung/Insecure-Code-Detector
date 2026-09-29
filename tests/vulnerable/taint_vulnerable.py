"""Intentionally vulnerable test fixture: taint flows (Phase 4). Never run this file."""
import os
import subprocess
import sys

from flask import request


def run_command():
    command = input("Command: ")
    os.system(command)  # expect: PY003


def ping():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)  # expect: PY004


def get_user(cursor):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # expect: PY011
    return cursor.fetchone()


def calculate():
    return eval(sys.argv[1])  # expect: PY001
