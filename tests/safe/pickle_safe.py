"""Safe counterpart of pickle_vulnerable.py."""
import json
import pickle


def load_session(cookie_value: str) -> dict:
    return json.loads(cookie_value)


def save_cache(path: str, data: dict) -> None:
    # Serializing with pickle is not the dangerous part; loading is.
    with open(path, "wb") as handle:
        pickle.dump(data, handle)
