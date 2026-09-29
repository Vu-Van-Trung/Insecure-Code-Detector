"""Safe counterpart of yaml_vulnerable.py."""
import yaml


def load_config(path: str):
    with open(path) as handle:
        return yaml.safe_load(handle)


def load_request_body(body: str):
    return yaml.load(body, Loader=yaml.SafeLoader)


def save_config(path: str, data: dict) -> None:
    with open(path, "w") as handle:
        yaml.safe_dump(data, handle)
