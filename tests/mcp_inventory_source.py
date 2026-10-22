"""Read declarations from the actual helper used by startup, without importing API."""

import ast


def configured_server_nodes(tree: ast.Module) -> ast.List:
    registration = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "register_optional_mcp_servers"
    )
    assignment = next(
        node.value
        for node in registration.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "servers" for target in node.targets)
    )
    assert isinstance(assignment, ast.Call)
    assert isinstance(assignment.func, ast.Name)
    assert assignment.func.id == "configured_mcp_server_specs"
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == assignment.func.id
    )
    declared = next(
        node.value
        for node in helper.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "configured" for target in node.targets
        )
    )
    assert isinstance(declared, ast.List)
    return declared
