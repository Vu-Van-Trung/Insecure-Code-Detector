"""Demo: the calculator rewritten without eval()/exec()."""
import ast
import operator

OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def evaluate(node: ast.AST) -> float:
    """Evaluate only numbers and + - * / (no names, calls or attributes)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATORS:
        return OPERATORS[type(node.op)](evaluate(node.left), evaluate(node.right))
    raise ValueError("Unsupported expression")


def calculate() -> None:
    expression = input("Enter an expression: ")
    tree = ast.parse(expression, mode="eval")
    print("Result:", evaluate(tree.body))


if __name__ == "__main__":
    calculate()
