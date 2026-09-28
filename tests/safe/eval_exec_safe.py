"""Safe counterpart of eval_exec_vulnerable.py."""
import ast
import operator

OPERATIONS = {"+": operator.add, "-": operator.sub}


def calculate(left: str, op: str, right: str) -> int:
    return OPERATIONS[op](int(left), int(right))


def parse_literal(text: str):
    return ast.literal_eval(text)


def evaluate(model):
    model.eval()  # e.g. a PyTorch model: not the builtin eval
    return model
