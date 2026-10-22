"""Conformance discovery follows the consolidated API and handles failed probes."""
import json

import pytest

from tests.conformance.mcp_client import ToolResult
from tests.conformance.run_conformance import probe_facts


class DiscoveryTransport:
    def __init__(self, listing):
        self.listing = listing
        self.calls = []

    def call_tool(self, name, arguments, timeout):
        self.calls.append(name)
        if name == "find_functions":
            return self.listing
        assert name == "find_data_types"
        return ToolResult(name, json.dumps({"data_types": [{"name": "Example"}]}), False)


def test_probe_uses_current_function_api_and_excludes_thunks():
    transport = DiscoveryTransport(ToolResult("find_functions", json.dumps({"functions": [
        {"name": "thunk", "address": "1000", "is_thunk": True},
        {"name": "external", "address": "2000", "is_external": True},
        {"name": "first", "address": "3000", "is_thunk": False, "is_external": False},
        {"name": "second", "address": "4000", "is_thunk": False, "is_external": False},
    ]}), False))
    facts = probe_facts(transport, "Benchmark.dll", "BenchmarkDebug.exe")
    assert facts.function_name == "first"
    assert facts.function_address == "0x3000"
    assert facts.second_function_address == "0x4000"
    assert facts.struct_name == "Example"
    assert transport.calls == ["find_functions", "find_data_types"]


def test_a_failed_discovery_reports_its_reason():
    transport = DiscoveryTransport(ToolResult("find_functions", "Program not found", True))
    with pytest.raises(SystemExit, match="Program not found"):
        probe_facts(transport, "missing", "second")
