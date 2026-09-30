"""Demo: application settings with credentials written in the code.

INTENTIONALLY VULNERABLE - for local testing of Secure Code Analyzer only.
All values are FAKE (the AWS key is the public example from the AWS documentation).
"""

DEBUG = False
SECRET_KEY = "3f8a9c1d7e2b4f6a8c0d1e3f5a7b9c2d4e6f8a0b"  # PY007 (high entropy)
DATABASE_PASSWORD = "SuperSecret123"  # PY007
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # PY007 (known format)


def connect(driver):
    return driver.connect(host="db.internal", user="app", password="Adm1n!2024")  # PY007
