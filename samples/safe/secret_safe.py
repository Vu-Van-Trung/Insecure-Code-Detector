"""Demo: the same settings loaded from the environment at runtime."""
import os

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["SECRET_KEY"]
DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")

PASSWORD_MIN_LENGTH = 12  # a setting about passwords, not a password


def connect(driver):
    return driver.connect(host="db.internal", user="app", password=DATABASE_PASSWORD)
