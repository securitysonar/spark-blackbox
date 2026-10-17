import ast

def is_number(node):
    return isinstance(node, ast.Num)
