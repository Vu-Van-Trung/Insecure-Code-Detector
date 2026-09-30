"""Intentionally vulnerable test fixture: PY005. Never run this file."""
import pickle  # expect: PY013

import pandas as pd


def load_session(cookie_value: bytes):
    return pickle.loads(cookie_value)  # expect: PY005


def load_cache(path: str):
    with open(path, "rb") as handle:
        return pickle.load(handle)  # expect: PY005


def load_upload(uploaded_path: str):
    return pd.read_pickle(uploaded_path)  # expect: PY005
