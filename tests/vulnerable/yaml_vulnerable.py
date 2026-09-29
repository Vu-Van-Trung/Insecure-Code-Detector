"""Intentionally vulnerable test fixture: PY006. Never run this file."""
import yaml


def load_config(path: str):
    with open(path) as handle:
        return yaml.load(handle)  # expect: PY006


def load_request_body(body: str):
    return yaml.load(body, Loader=yaml.Loader)  # expect: PY006


def load_all(body: str):
    return yaml.unsafe_load(body)  # expect: PY006


def load_full(body: str):
    return yaml.full_load(body)  # expect: PY006
