"""A small, safe arithmetic evaluator (replaces ``eval``)."""

from __future__ import annotations

import ast
import math
import operator

_BIN = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}
_FUNCS = {name: getattr(math, name) for name in (
    "sqrt", "cbrt", "exp", "log", "log2", "log10", "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "sinh", "cosh", "tanh", "degrees", "radians", "floor", "ceil", "factorial", "gcd", "lcm", "hypot",
    "fabs", "trunc", "isqrt", "comb", "perm",
) if hasattr(math, name)}
_FUNCS.update({"abs": abs, "round": round, "min": min, "max": max, "sum": lambda *a: sum(a)})
_CONSTS = {"pi": math.pi, "e": math.e, "tau": math.tau, "inf": math.inf}

MAX_LEN = 300
MAX_POW = 10_000
MAX_FACTORIAL = 1000


class CalcError(ValueError):
    pass


def safe_eval(expression: str) -> int | float:
    if len(expression) > MAX_LEN:
        raise CalcError(f"Expression longer than {MAX_LEN} characters.")
    try:
        tree = ast.parse(expression.replace("^", "**"), mode="eval")
    except SyntaxError as exc:
        raise CalcError(f"Invalid expression: {exc.msg}") from None
    return _eval(tree.body)


def _eval(node: ast.AST) -> int | float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name) and node.id in _CONSTS:
        return _CONSTS[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > MAX_POW:
            raise CalcError("Exponent too large.")
        return _BIN[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _UNARY[type(node.op)](_eval(node.operand))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FUNCS and not node.keywords:
        args = [_eval(a) for a in node.args]
        if node.func.id == "factorial" and args and args[0] > MAX_FACTORIAL:
            raise CalcError("factorial argument too large.")
        return _FUNCS[node.func.id](*args)
    raise CalcError(f"Unsupported element in expression: {ast.dump(node)[:60]}")
