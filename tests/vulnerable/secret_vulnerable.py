"""Intentionally vulnerable test fixture: PY007. Never run this file.

All values are fake. The AWS key is the public example from the AWS documentation.
"""

API_KEY = "a8f5f167f44f4964e6c998dee827110c"  # expect: PY007
DB_PASSWORD = "admin123"  # expect: PY007
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # expect: PY007


class MailClient:
    def __init__(self):
        self.smtp_password = "Tr0ub4dor&3"  # expect: PY007


def connect(driver):
    return driver.connect(host="db.local", user="app", password="P@ssw0rd2024")  # expect: PY007


SETTINGS = {
    "debug": False,
    "secret_key": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c",  # expect: PY007
}
