# Fork integration: upstream 7.0.0

Baseline: upstream tag `v7.0.0` (`001145c3`, release tree `19e64c75`),
published October 21, 2026. Fork starting point: `18081bd6`.

## Included changes

The integration includes the complete stable release: transaction/save fixes,
program targeting, shared GUI/headless services and transports, MCP error and
annotation handling, consolidated tools, documentation application, language-variant
labelling, memory-block controls, and the upstream test/release infrastructure.

Two selected changes from upstream development are adapted to the stable API:

- `cf8b12db` (#575): request-scoped decompiler reuse and per-entry-point results.
  Metadata-only reads open no decompiler. Failed decompilation disposes the
  interface so subsequent functions can reopen it.
- `c008651b` (#602): exact signed 32-bit integer binding and object-array
  validation. Malformed inputs fail before the tool runs. This does not bring
  over development's broader typed-program/function parameter refactor.

## Consumer migration

Update external scripts, saved prompts and tool allowlists together with the
extension and bridge. The extension targets Ghidra **12.1.4** and Java **21**.

| Earlier fork call | Current call |
| --- | --- |
| `decompile_function(address=...)` | `get_functions(function=..., fields="decompiled_code")` |
| `list_functions` / `search_functions` | `find_functions` |
| `get_bulk_xrefs(addresses=[...])` | `get_xrefs_to(addresses="a,b,c")` |
| `batch_apply_documentation` | `apply_documentation(entries=[...])` |
| `apply_function_documentation` | `apply_documentation` with typed parameters |
| `list_data_types` / `search_data_types` | `find_data_types` |
| `load_program_from_project` | `open_program`, or pass `program` to the desired tool |
| headless `health` | `check_connection` |

See [the complete upstream migration guide](MIGRATION_7.0.0_TOOL_CONSOLIDATION.md)
for the remaining renamed tools and parameter changes. Explicitly target a
program when several programs are open.

## Fork behavior preserved

- `disassemble_bytes`: executable-memory restriction and `follow_flow` remain
  independent. The default bounds disassembly to the requested range. The
  implementation also retains upstream's `WriteTx` nesting protection and
  threading strategy.
- `search_byte_patterns`: malformed hex is refused; nibble wildcards are
  supported; results report truncation and memory coverage, including unreadable
  blocks. Wildcards belong in `pattern`; there is no separate `mask` parameter.
- Single cross-reference reads retain `resolved_address`, `in_memory_block`, and
  `block` when mapped. Bulk `get_xrefs_to` keeps the upstream
  `references_by_address` wrapper, but each value is an object containing either
  references and mapping information or an `error`. Consumers that previously
  expected a bare reference array must read the value's `references` field.
- Bulk `get_functions` retains typed per-function errors. `count` is successful
  reads, `requested` is processed inputs, `total` is all nonempty input references,
  and `truncated` is always explicit. Over-cap requests also report a note and cap.
- Conformance generation retains the schema-error fallback and discovers
  functions using `find_functions` rather than the retired listing tool.

The oracle removal is already part of upstream. The old bulk decompilation tool
is replaced by `get_functions`; its safety properties are preserved on that
public API rather than restoring the retired tool.

## Validation

Validation uses a temporary Ghidra 12.1.4 installation and the existing Java 21
runtime. The archive does not contain a macOS decompiler, so its native source
was built for Apple Silicon inside that temporary installation.

- Python unit and offline HTTP suites: **1,276 passed, 13 skipped**.
- Java suites: **907 passed, zero failures or skips** (848 offline tests and 59
  real-Ghidra tests), including decompiler reuse, recovery after
  interface failure, language variants, strict binding, bounded disassembly,
  nested transactions and mixed valid/invalid cross-reference batches.
- Read-only endpoint integration replay: **54 passed, 17 fixture-dependent skips**.
- An isolated headless server with the bundled `Benchmark.dll`, driven through
  the actual stdio MCP bridge: project creation/import, decompilation, bulk
  truncation, cross-reference mapping/errors, pattern validation, parameter aliases
  and fractional integer refusal.
- Endpoint catalog regeneration, server-scope audit, README reference generation,
  extension packaging and Python wheel build.

The temporary live project is separate from the user's projects. GUI interaction,
Windows debugger attachment and a shared Ghidra Server were not exercised locally.
