# x64dbgMCP Improved

This repository contains a patched and extended build of the x64dbg MCP/HTTP plugin used for remote-assisted x32dbg/x64dbg debugging.

Original upstream project:

<https://github.com/Wasdubya/x64dbgMCP>

This fork keeps the upstream plugin idea intact, but adds safer remote debugging behavior for LAN-based workflows and fixes a practical deadlock risk around full-speed run/step commands.

## Why This Fork Exists

The upstream plugin starts an HTTP server inside x64dbg/x32dbg and exposes debugger operations such as memory reads, register reads, breakpoints, and debug control commands.

During reverse engineering work with x32dbg inside a Windows VM, two limitations became important:

1. The HTTP server was hard-bound to `127.0.0.1`, so macOS or another host on the LAN could not connect directly.
2. Synchronous `/Debug/Run` and `/Debug/Step*` requests could block the plugin HTTP server thread, making the bridge appear frozen after asking the debugger to run.

This fork addresses those two issues while preserving the original command style.

## Main Changes

- Added configurable HTTP listen host via the `httphost` x64dbg command.
- Kept the default bind address as `127.0.0.1` for safety.
- Added `/Health`, `/health`, and `/healthz` endpoints.
- Disabled synchronous `/Debug/Run`, `/Debug/Pause`, `/Debug/Stop`, `/Debug/StepIn`, `/Debug/StepOver`, and `/Debug/StepOut`.
- Added asynchronous debug-control endpoints:
  - `/Debug/RunAsync`
  - `/Debug/PauseAsync`
  - `/Debug/StopAsync`
  - `/Debug/StepInAsync`
  - `/Debug/StepOverAsync`
  - `/Debug/StepOutAsync`
- Added a debug action worker thread so async run/step requests return immediately.
- Added a plugin-side event buffer plus HTTP log endpoints so remote clients can read recent breakpoint/debug-string events without scraping the x64dbg GUI log window.
- Added a socket receive timeout to avoid stalled client connections blocking the HTTP thread.
- Disabled the old synchronous `/Disasm/StepInWithDisasm` endpoint because it performed a direct step inside the HTTP request handler.
- Fixed HTTP server start/stop state handling to avoid a potential self-lock/restart issue.

## Safety Note

Binding this plugin to `0.0.0.0` exposes powerful debugger operations to the LAN. Anyone who can reach the port may be able to read/write process memory, set breakpoints, alter registers, or run debugger commands.

Recommended default:

```text
httphost 127.0.0.1
```

Use LAN mode only on a trusted network:

```text
httphost 0.0.0.0
```

## Building With GitHub Actions

The project uses CMake and MSVC. It should be built on Windows, not Ubuntu/macOS.

The existing `CMakeLists.txt` supports a superbuild that produces both `.dp32` and `.dp64` artifacts. The workflow should:

1. Run on `windows-latest`.
2. Create the `deps/` directory before CMake configures.
3. Configure with `-DX64DBG_DOWNLOAD_SDK=ON`.
4. Build the `all_plugins` target.
5. Upload `.dp32` and `.dp64` files.

Example workflow:

```yaml
name: Build x64dbgMCP

on:
  workflow_dispatch:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

env:
  BUILD_TYPE: Release

jobs:
  build:
    runs-on: windows-latest

    steps:
      - uses: actions/checkout@v4

      - name: Ensure deps directory exists
        shell: pwsh
        run: New-Item -ItemType Directory -Force -Path "${{ github.workspace }}/deps"

      - name: Configure CMake superbuild
        run: >
          cmake -S "${{ github.workspace }}"
          -B "${{ github.workspace }}/build"
          -G "Visual Studio 17 2022"
          -DX64DBG_DOWNLOAD_SDK=ON
          -DBUILD_BOTH_ARCHES=ON

      - name: Build x32 and x64 plugins
        run: >
          cmake --build "${{ github.workspace }}/build"
          --config ${{ env.BUILD_TYPE }}
          --target all_plugins
          --verbose

      - name: List build outputs
        shell: pwsh
        run: |
          Get-ChildItem -Path "${{ github.workspace }}/build" -Recurse |
            Where-Object { $_.Name -match '\.(dp32|dp64|lib|dll|exe)$' } |
            Select-Object FullName, Length |
            Format-Table -AutoSize

      - name: Upload plugin artifacts
        uses: actions/upload-artifact@v4
        with:
          name: x64dbgMCP-plugins
          path: |
            ${{ github.workspace }}/build/**/*.dp32
            ${{ github.workspace }}/build/**/*.dp64
          if-no-files-found: error
```

## Installation

Use the plugin that matches the debugger architecture:

- `MCPx64dbg.dp32` for x32dbg.
- `MCPx64dbg.dp64` for x64dbg.

For a 32-bit target process, install the `.dp32` file into the x32dbg plugin directory, for example:

```text
C:\path\to\x64dbg\release\x32\plugins\MCPx64dbg.dp32
```

For a 64-bit target process, install the `.dp64` file into:

```text
C:\path\to\x64dbg\release\x64\plugins\MCPx64dbg.dp64
```

Restart x32dbg/x64dbg after replacing the plugin.

## Basic Usage

By default, the plugin listens on localhost:

```text
http://127.0.0.1:8888/
```

Check local health:

```text
http://127.0.0.1:8888/Health
```

Expected response shape:

```json
{
  "ok": true,
  "service": "x64dbg_mcp_plugin",
  "listenHost": "127.0.0.1",
  "port": 8888,
  "debugging": true,
  "running": false
}
```

To expose the plugin to the LAN, run this in the x32dbg/x64dbg command bar:

```text
httphost 0.0.0.0
```

Then connect from another machine:

```text
http://<vm-ip>:8888/Health
```

Example:

```text
http://192.168.79.128:8888/Health
```

To change the port:

```text
httpport 8889
```

To toggle the HTTP server:

```text
httpserver
```

## Reading Recent Events

The plugin now keeps a small in-memory event buffer that remote clients can read directly. This is intended for cases where x64dbg GUI breakpoint logging is unreliable or hard to scrape remotely.

Current event kinds:

- `breakpoint`: emitted from the official `CB_BREAKPOINT` plugin callback and includes breakpoint metadata such as address, hit count, conditions, and configured log/command text.
- `output_debug_string`: emitted from `CB_OUTPUTDEBUGSTRING` when the debuggee calls `OutputDebugString`.

Read the newest buffered entries:

```text
/Log/Recent?limit=100
```

Read entries newer than a prior sequence id:

```text
/Log/Recent?since=250&limit=50
```

Read and clear in one request:

```text
/Log/Recent?limit=100&clear=true
```

Clear the buffer explicitly:

```text
/Log/Clear
```

Example response:

```json
{
  "count": 2,
  "totalBuffered": 2,
  "entries": [
    {
      "seq": 41,
      "tickMs": 381245,
      "kind": "breakpoint",
      "text": "addr=0x4c223b type=normal hitCount=3531 module=musicbox15 breakCondition=[ebp-0x0c]==0x4D10&&eax==0x42"
    },
    {
      "seq": 42,
      "tickMs": 381910,
      "kind": "output_debug_string",
      "text": "WT_19728_row72 tick=4D10 eax=42 eip=004C223B"
    }
  ]
}
```

## Legacy Breakpoint Action Caveats

This fork still exposes the older breakpoint-management surface through x64dbg commands and `/Breakpoint/List`, but real-world tracing showed that the legacy GUI breakpoint action workflow is not a reliable source of truth for remote automation.

Observed problems during MusicBox15 reverse-engineering:

- `Breakpoint/List` only reports the configured breakpoint fields such as `breakCondition`, `logText`, and `commandText`. It does not prove that x64dbg actually evaluated those fields the way the GUI suggests at runtime.
- Complex breakpoint conditions could be present in `Breakpoint/List` and still behave inconsistently at execution time.
- GUI-side `log` / `pause` behavior depended on which condition field was used (`breakCondition`, log condition, command condition), and those layers were not trustworthy enough for bridge-driven auditing.
- Scraping the x64dbg GUI log window is brittle and should not be treated as a stable machine-readable API.

Practical guidance:

- Prefer `/Log/Recent` and `/Log/Clear` for breakpoint-hit auditing.
- Treat `/Breakpoint/List` as configuration/state introspection, not as proof that a breakpoint command or condition executed as intended.
- If you must use `SetBreakpointCommand` or `SetBreakpointLog`, quote the full text payload explicitly. For example:

```text
SetBreakpointCommand 0x004C223B,"log \"probe cmd with spaces\""
SetBreakpointLog 0x004C223B,"probe log with spaces"
```

- `SetBreakpointSilent` has an additional practical quirk in this workflow:
  - `SetBreakpointSilent addr,1` reliably enabled the flag.
  - `SetBreakpointSilent addr,0` did not reliably clear it.
  - On a plain breakpoint with no extra breakpoint metadata, `SetBreakpointSilent addr` (omitting `arg2`) could clear it.
  - Once breakpoint metadata such as a custom condition, log text, or command text had been configured, the silent flag could remain sticky even after trying to clear it remotely.
- Because of that behavior, this fork now provides a dedicated verified endpoint for software breakpoints:

```text
/Breakpoint/SetSilent?addr=0x004C223B&silent=true
/Breakpoint/SetSilent?addr=0x004C223B&silent=false
```

The endpoint retries the known x64dbg command variants internally and then verifies the final state through `Breakpoint/List`.

- For new automation work, prefer plugin-captured callback events over GUI log scraping or GUI-only conditional actions.

## Debug Run Behavior

The synchronous debug control endpoints are intentionally disabled:

```text
/Debug/Run
/Debug/Pause
/Debug/Stop
/Debug/StepIn
/Debug/StepOver
/Debug/StepOut
```

They return `409 Conflict` with a JSON error message. This avoids blocking the HTTP server thread.

Use the async endpoints instead:

```text
/Debug/RunAsync
/Debug/PauseAsync
/Debug/StopAsync
/Debug/StepInAsync
/Debug/StepOverAsync
/Debug/StepOutAsync
```

Example:

```text
http://192.168.79.128:8888/Debug/RunAsync
```

Expected response:

```json
{
  "queued": true,
  "action": "Run"
}
```

The request returns immediately. The debugger action is executed by a background worker thread.

## Useful Inspection Endpoints

Beyond the async debug-control changes, this fork already exposes several endpoints that are useful for live reverse-engineering and stack/frame inspection workflows.

### Expression Evaluation

`/Misc/ParseExpression` forwards to x64dbg's expression parser and returns a numeric `duint` result.

This is often more robust than manually converting stack-slot indices because x64dbg evaluates the expression in the current paused CPU context.

Examples:

```text
/Misc/ParseExpression?expression=cip
/Misc/ParseExpression?expression=ebp
/Misc/ParseExpression?expression=[ebp-0x2c]
/Misc/ParseExpression?expression=[esp+4]
```

When `format=json` is supplied, the response shape is:

```json
{
  "ok": true,
  "value": "0x12345678"
}
```

This endpoint is especially handy for reading frame-local variables such as `[ebp-0x2c]` without first translating them into `Stack/Peek` offsets.

### Register Snapshot

`/RegisterDump` returns a full register snapshot in one call. It wraps `DbgGetRegDumpEx(...)` and includes:

- General-purpose registers
- `cip` / instruction pointer
- `eflags` plus decoded flag bits
- Segment registers
- Debug registers
- Last error / last status fields

This is preferable to many individual `/Register/Get` calls when the debugger is paused and a consistent register view matters.

### Call Stack Snapshot

`/GetCallStack` returns the current call stack using `GetCallStackEx(...)`, including:

- The current address for each frame
- Caller/callee addresses
- x64dbg-generated comments or symbol names when available

This is useful when a breakpoint can be hit from more than one path and the current frame needs to be disambiguated before reading locals.

### Stack Helpers

The plugin also exposes:

```text
/Stack/Pop
/Stack/Push
/Stack/Peek
```

`/Stack/Peek` is a thin wrapper over `Script::Stack::Peek(offset)`. It is convenient for top-of-stack inspection, but for frame-local reads such as `[ebp-0x2c]` or `[rbp-0x30]`, `/Misc/ParseExpression` is usually the safer choice.

## Tested Workflow

The improved plugin has been tested in this workflow:

- Host: macOS.
- Debugger: x32dbg inside a Windows VM.
- Target: 32-bit Windows executable.
- Plugin: `MCPx64dbg.dp32`.
- LAN endpoint: `http://192.168.79.128:8888/`.

Observed behavior:

- LAN access works after `httphost 0.0.0.0`.
- `/Debug/RunAsync` returns immediately with `{"queued":true,"action":"Run"}`.
- The debugger can still be queried remotely after async run requests.

## Python Client Helper

This repository also includes a Python helper, `x64dbg.py`, for driving the x64dbgMCP HTTP API from another process or another machine.

The local helper has been adjusted to work better with the improved plugin:

- Default debugger URL can be overridden with the `X64DBG_URL` environment variable.
- The debugger URL can also be supplied as the first positional argument when it starts with `http`.
- `safe_get()` uses a longer timeout for debugger operations that may take a moment.
- `safe_post()` keeps a shorter timeout so stalled POST requests fail quickly.
- `IsDebugging()` and `IsDebugActive()` parse JSON responses from the improved plugin.
- Added `DebugRunAsync()` as a wrapper for `/Debug/RunAsync`.
- Added `DebugPauseAsync()` as a wrapper for `/Debug/PauseAsync`.
- Added internal tool-registry helpers so MCP tool functions can be listed and invoked by name.
- Added an optional Claude/Anthropic CLI path that can expose the debugger tools to an LLM-driven workflow.

Operational notes that mattered in practice:

- Many endpoints intentionally return plain text rather than JSON.
  - Examples: `MemoryRead`, `RegisterGet`, `StackPeek`, `MiscParseExpression`
  - If a one-off helper blindly `json.loads()` every `200 OK` body, it will mis-handle these endpoints.
- The CLI wrapper uses positional arguments, not `key=value` pairs.
  - Correct:
    - `x64dbgvenv/bin/python x64dbg.py RegisterGet --x64dbg-url http://192.168.79.128:8888/ eax`
    - `x64dbgvenv/bin/python x64dbg.py DebugSetBreakpoint --x64dbg-url http://192.168.79.128:8888/ 0x004C231C`
  - Incorrect:
    - `... RegisterGet eax=...`
    - `... DebugSetBreakpoint addr=0x004C231C`
- For frame-local values in a paused function, prefer `MiscParseExpression("[ebp-0x2c]")` or `MiscParseExpression("[rsp+8]")` over `StackPeek`.
  - `StackPeek` is indexed relative to the current stack top.
  - It is useful for stack-top inspection, but it is not a stable shorthand for frame locals across every paused state.
- `RegisterDump` is the preferred way to capture a consistent paused-state register snapshot.
- `GetBreakpointList` can lag briefly behind recent breakpoint mutations.
  - Safe pattern: mutate debugger state -> wait briefly -> query state.

Typical local usage:

```bash
x64dbgvenv/bin/python x64dbg.py
```

With an explicit debugger URL:

```bash
X64DBG_URL=http://192.168.79.128:8888/ x64dbgvenv/bin/python x64dbg.py
```

Examples with positional tool arguments:

```bash
x64dbgvenv/bin/python x64dbg.py RegisterGet --x64dbg-url http://192.168.79.128:8888/ eax
x64dbgvenv/bin/python x64dbg.py MiscParseExpression --x64dbg-url http://192.168.79.128:8888/ "[ebp-0x2c]"
x64dbgvenv/bin/python x64dbg.py GetRegisterDump --x64dbg-url http://192.168.79.128:8888/
```

For GUI targets or any target expected to keep running, prefer the async wrappers:

```text
DebugRunAsync()
DebugPauseAsync()
```

Avoid synchronous `/Debug/Run` for long-running debuggees because it can block the HTTP request path in older plugin builds.

## Troubleshooting

If `httphost` is not recognized, x32dbg is still loading the old plugin. Make sure the rebuilt `.dp32` file was copied into the x32dbg plugin directory and that x32dbg was restarted.

If the startup log says:

```text
x64dbg HTTP Server started on port 8888
```

that is the old version. The improved version logs:

```text
x64dbg HTTP Server started on 127.0.0.1:8888
```

If LAN access does not work:

1. Confirm `httphost 0.0.0.0` was executed.
2. Confirm Windows Firewall allows inbound TCP on the selected port.
3. Confirm the correct IP address with `ipconfig`.
4. Test locally first with `http://127.0.0.1:8888/Health`.

If GitHub Actions compiles but the new commands are missing, verify that the modified source was placed in:

```text
src/MCPx64dbg.cpp
```

The CMake project uses:

```cmake
file(GLOB SOURCES "src/*.cpp")
```

so a modified `MCPx64dbg.cpp` in the repository root will not be compiled.

## License And Attribution

This work is based on the original x64dbgMCP project:

<https://github.com/Wasdubya/x64dbgMCP>

Please refer to the upstream repository for original licensing and attribution details.
