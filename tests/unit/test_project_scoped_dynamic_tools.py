import inspect
from unittest.mock import patch

from bridge_mcp_ghidra.registry import _build_tool_function


def test_dynamic_tool_signature_requires_project_id():
    fn = _build_tool_function(
        "/decompile_function",
        "GET",
        {
            "properties": {
                "address": {"type": "string"},
                "program": {"type": "string", "default": ""},
            },
            "required": ["address"],
        },
    )

    signature = inspect.signature(fn)
    project_id = signature.parameters["project_id"]

    assert project_id.kind is inspect.Parameter.KEYWORD_ONLY
    assert project_id.default is inspect.Parameter.empty
    assert project_id.annotation is str


def test_project_id_is_routing_only_and_never_forwarded_to_java():
    fn = _build_tool_function(
        "/decompile_function",
        "GET",
        {
            "properties": {
                "address": {"type": "string"},
                "program": {"type": "string", "default": ""},
            },
            "required": ["address"],
        },
    )

    with patch("bridge_mcp_ghidra.dispatch.dispatch_get", return_value='{"data":{}}') as call:
        fn(project_id="ghp_deadbeef", address="0x401000", program="firmware")

    call.assert_called_once_with(
        "/decompile_function",
        params={"address": "0x401000", "program": "firmware"},
    )
