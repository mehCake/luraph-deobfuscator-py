# Sandbox Policy

## Overview

The tooling in this repository interacts with potentially hostile Lua payloads. To
avoid side effects we execute any dynamic analysis inside a heavily restricted
sandbox. This document outlines the design for those sandboxes, the surface area
that is intentionally exposed, and the fake APIs we provide so that bootstrap
code can proceed without touching the host environment.

## Goals

* Prevent disk, network, and process side effects.
* Guarantee deterministic behaviour regardless of host OS.
* Ensure session keys or other sensitive data are never persisted by sandboxed
  code.
* Support Luraph 14.4.1–14.4.3 payloads, with special handling for the
  14.4.2-specific bootstrap helpers embedded in `Obfuscated3.lua`.

## Execution Environment

* **Runtime** – We embed Lua via `lupa` when available. When `lupa` is missing we
  fall back to a lightweight interpreter that evaluates a small subset of Lua in
  pure Python.
* **Entry Point** – Sandboxed runs load extracted bootstrap snippets or handler
  tests, never the full obfuscated script. All inputs are normalised to UTF-8
  and stripped of NUL bytes before execution.
* **Timeouts** – Each sandbox invocation has a strict instruction or wall-clock
  timeout (default 3 seconds) to prevent infinite loops. Callers may override
  this with explicit flags.
* **Resource Limits** – The sandbox limits memory by constraining table sizes and
  the number of generated coroutines. Any attempt to exceed those thresholds
  raises a `SandboxLimitError` that is propagated to the caller.

## Allowed APIs

Only the following APIs are available to sandboxed code:

| API             | Behaviour                                                     |
|-----------------|----------------------------------------------------------------|
| `math`, `bit32` | Read-only access to standard numeric helpers.                 |
| `string`        | Read-only (no `string.dump`).                                 |
| `table`         | Standard table helpers.                                       |
| `coroutine`     | Allowed for payloads that rely on coroutine-driven VMs.       |
| `utf8`          | Minimal subset required by certain bootstrap versions.       |

All other globals are removed or replaced with safe stubs. The sandbox also
injects a small `sandbox` table that exposes logging helpers (`sandbox.log`)
which forward messages to the Python host for debugging without allowing the Lua
code to mutate host state.

## Stub Implementations

We provide deterministic stubs for APIs that are frequently referenced by
Luraph bootstraps but would normally have side effects:

### `io` Stub

```lua
io = {}
function io.open(path, mode)
  sandbox.log("io.open called", path, mode)
  return nil, "sandboxed: filesystem unavailable"
end

function io.read(...)
  return nil, "sandboxed"
end

function io.write(...)
  sandbox.log("io.write suppressed")
  return false
end
```

### `os` Stub

```lua
os = {
  clock = os_clock_stub,
  time = function() return sandbox.time_hint end,
  date = function() return "1970-01-01" end
}

function os_clock_stub()
  return sandbox.elapsed_hint
end
```

The `sandbox.time_hint` and `sandbox.elapsed_hint` values are injected from the
host to give deterministic timestamps without touching the real clock. Dangerous
functions such as `os.execute`, `os.remove`, `os.rename`, and environment access
raise explicit errors.

### `require` Stub

```lua
function require(name)
  sandbox.log("require suppressed", name)
  return nil
end
```

Version 14.4.2 bootstraps often probe for helper modules such as `initv4`. The
stub responds with `nil` so the bootstrap falls back to the inlined routines.

## Additional Guards for v14.4.2

`Obfuscated3.lua` embeds the bootstrap logic directly rather than relying on an
external `initv4`. For that reason the sandbox:

* Preloads the extracted bootstrap chunk with the session key provided via CLI
  (never stored on disk) and clears the key from memory once the chunk returns.
* Blocks attempts to read the original obfuscated file path.
* Ensures that the fake `io` and `os` modules behave consistently with the
  expectations of the 14.4.2 handler tests.

## Commented Example

Below is a condensed bootstrap harness showing the stub injection flow:

```python
from lupa import LuaRuntime

SANDBOX_STUB = """
local sandbox = ...
_G.io = sandbox.io_stub()
_G.os = sandbox.os_stub()
_G.require = sandbox.require_stub
"""

runtime = LuaRuntime(unpack_returned_tuples=True)
runtime.execute(SANDBOX_STUB, sandbox_context)
```

The `sandbox_context` provides the functions described above and strips any
fields containing `key`, `secret`, or `token` before execution to avoid leaks.

## Testing

* Unit tests cover the stub behaviour and ensure attempts to call restricted
  APIs raise errors.
* Integration tests run representative bootstraps (including the v14.4.2 sample)
  to confirm decoding still succeeds under the restricted environment.

## Operational Checklist

1. Provide the session key via CLI or stdin when required; never bake it into
   files.
2. Run `python -m src.tools.ensure_no_keys` after analysis to confirm no artefact
   leaks occurred.
3. When collecting runtime traces, use the sandbox stubs above and disable any
   optional features that could trigger I/O.
4. Document any additional APIs exposed for future Luraph versions in this file
   before shipping changes.

## Change History

* **2024-xx-xx** – Initial version with 14.4.2-specific notes.
