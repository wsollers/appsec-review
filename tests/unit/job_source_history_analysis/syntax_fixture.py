"""Synthetic Python concrete-node fixture retained from the pre-walk emulator."""
import ast


class _Node:
    def __init__(self, kind, start, end, field=None, named=True):
        self.kind, self.start, self.end, self.field, self.named, self.children = kind, start, end, field, named, []


def tree_sitter_nodes(source: bytes) -> list[dict]:
    offsets = [0]
    for line in source.split(b"\n"):
        offsets.append(offsets[-1] + len(line) + 1)
    lines = source.split(b"\n")

    def node(kind, item, field=None):
        return _Node(kind, (item.lineno, item.col_offset), (item.end_lineno, item.end_col_offset), field)

    def statements(parent, body):
        for statement in body:
            visit(parent, statement)

    def visit(parent, item, field=None):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            current = node("class_definition" if isinstance(item, ast.ClassDef) else "function_definition", item, field)
            column = lines[item.lineno - 1].find(item.name.encode(), item.col_offset)
            current.children.append(_Node("identifier", (item.lineno, column),
                                          (item.lineno, column + len(item.name)), "name"))
            parent.children.append(current)
            statements(current, item.body)
        elif isinstance(item, ast.If):
            current = node("if_statement", item, field)
            parent.children.append(current)
            visit(current, item.test, "condition")
            statements(current, item.body)
            orelse = item.orelse
            while orelse:
                first = orelse[0]
                if (len(orelse) == 1 and isinstance(first, ast.If) and
                        lines[first.lineno - 1].lstrip().startswith(b"elif")):
                    clause = node("elif_clause", first, "alternative")
                    current.children.append(clause)
                    visit(clause, first.test, "condition")
                    statements(clause, first.body)
                    orelse = first.orelse
                else:
                    clause = _Node("else_clause", (first.lineno, first.col_offset),
                                   (orelse[-1].end_lineno, orelse[-1].end_col_offset), "alternative")
                    current.children.append(clause)
                    statements(clause, orelse)
                    orelse = []
        elif isinstance(item, (ast.For, ast.While)):
            current = node("for_statement" if isinstance(item, ast.For) else "while_statement", item, field)
            parent.children.append(current)
            statements(current, item.body)
        elif isinstance(item, ast.IfExp):
            current = node("conditional_expression", item, field)
            parent.children.append(current)
            for child in (item.body, item.test, item.orelse):
                visit(current, child)
        elif isinstance(item, ast.Lambda):
            current = node("lambda", item, field)
            parent.children.append(current)
            visit(current, item.body, "body")
        elif isinstance(item, ast.BoolOp):
            token = "and" if isinstance(item.op, ast.And) else "or"
            left = item.values[0]
            for right in item.values[1:]:
                combined = _Node("boolean_operator", (item.lineno, item.col_offset),
                                 (right.end_lineno, right.end_col_offset), field)
                if isinstance(left, _Node):
                    left.field = "left"
                    combined.children.append(left)
                else:
                    visit(combined, left, "left")
                combined.children.append(_Node(token, (right.lineno, right.col_offset),
                                               (right.lineno, right.col_offset), "operator", named=False))
                visit(combined, right, "right")
                left = combined
            parent.children.append(left)
        else:
            for child in ast.iter_child_nodes(item):
                visit(parent, child)

    root = _Node("module", (1, 0), (len(lines), len(lines[-1])))
    statements(root, ast.parse(source.decode()).body)
    output = []

    def emit(current, ordinal):
        (start_line, start_column), (end_line, end_column) = current.start, current.end
        output.append({"ordinal_path": list(ordinal), "field": current.field, "type": current.kind,
                       "named": current.named, "error": False, "missing": False, "extra": False, "has_error": False,
                       "start_byte": offsets[start_line - 1] + start_column, "end_byte": offsets[end_line - 1] + end_column,
                       "start_point": [start_line - 1, start_column], "end_point": [end_line - 1, end_column]})
        for index, child in enumerate(current.children):
            emit(child, (*ordinal, index))

    emit(root, ())
    return output
