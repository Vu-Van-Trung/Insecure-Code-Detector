"""Safe counterpart of secret_vulnerable.py: secrets are loaded at runtime."""
import os

API_KEY = os.environ["API_KEY"]
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")

# Metadata about secrets and obvious placeholders are not secrets.
PASSWORD_MIN_LENGTH = 12
TOKEN_URL = "https://auth.example.com/oauth/token"
API_KEY_HEADER = "X-API-Key"
EXAMPLE_PASSWORD = "changeme"
TOKEN_ENV_VAR = "GITHUB_TOKEN"


class MailClient:
    def __init__(self, password: str):
        self.smtp_password = password


def connect(driver):
    return driver.connect(host="db.local", user="app", password=os.environ["DB_PASSWORD"])
