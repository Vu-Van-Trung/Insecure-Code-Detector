"""PY005 - Deserialize không an toàn bằng pickle và các thư viện tương thích pickle."""

from app.models.finding import Severity
from app.rules.base import DangerousCallRule
from app.rules.registry import register_rule

# Module dùng định dạng pickle (_pickle/cPickle là bản C; dill mở rộng pickle).
_PICKLE_MODULES = ("pickle", "_pickle", "cPickle", "dill")
_LOAD_FUNCTIONS = ("load", "loads", "Unpickler")


@register_rule
class PickleRule(DangerousCallRule):
    """PY005: dữ liệu pickle có thể chứa lệnh được thực thi ngay khi nạp."""

    id = "PY005"
    name = "Unsafe deserialization with pickle"
    description = (
        "Unpickling runs code chosen by whoever created the data: a crafted pickle "
        "can call os.system() through __reduce__ during loading. Data from a network, "
        "upload, cookie, cache or any file an attacker can modify must never be unpickled."
    )
    severity = Severity.HIGH
    cwe = "CWE-502"
    category = "Insecure Deserialization"
    recommendation = (
        "Use a data-only format such as JSON for untrusted data. If pickle is "
        "required, only load data you created yourself and verify its integrity "
        "(e.g. an HMAC signature) before unpickling."
    )
    # Ghi dữ liệu (dump/dumps) an toàn; chỉ việc NẠP mới bị báo.
    # Tạo mọi tổ hợp module x hàm: pickle.load, pickle.loads, dill.Unpickler...
    target_functions = frozenset(
        {f"{module}.{function}" for module in _PICKLE_MODULES for function in _LOAD_FUNCTIONS}
        | {"pandas.read_pickle"}
    )
    dynamic_message = "{name}() deserializes data that may be attacker-controlled."
    static_message = "{name}() deserializes constant data; verify pickle is really needed."
    static_confidence = 0.5
