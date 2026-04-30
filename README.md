# x64dbgMCP Improved

This repository contains a patched and extended build of the x64dbg MCP/HTTP plugin used for remote-assisted x32dbg/x64dbg debugging.

Operational rule for this repository:

- do not rely on historical hard-coded VM IPs
- prefer an explicit `--x64dbg-url http://<vm-ip>:8888/` for LAN sessions
- MusicBox15 helper scripts also accept `--url` as a backward-compatible alias
- or set `X64DBG_URL` in the shell before running helper scripts
- if neither is set, local helper scripts now fall back to `http://127.0.0.1:8888/`
- for HostExec helpers, you can also preconfigure:
  - `X64DBG_REMOTE_PYTHON`
  - `X64DBG_REMOTE_POWERSHELL`
  - `X64DBG_HOSTEXEC_CWD`
  - `X64DBG_HOSTEXEC_TIMEOUT_MS`
- `x64dbg_tools/x64dbg.py` now supports both:
  - module execution: `python -m x64dbg_tools.x64dbg ...`
  - direct script execution: `python x64dbg_tools/x64dbg.py ...`

Use this README for the local role of `x64dbg_tools/` and the generic bridge
tooling surface. For repository-wide navigation, use
`docs/functional_file_map.md`. For placement rules, use
`docs/file_organization_rules.md`. For MusicBox15-specific helper assets, use
`x64dbg_tools/musicbox15/README.md`. For wrapper and migration history, use
`docs/repository_reorganization_audit.md`.

Original upstream project:

<https://github.com/Wasdubya/x64dbgMCP>

This fork keeps the upstream plugin idea intact, but adds safer remote debugging behavior for LAN-based workflows and fixes a practical deadlock risk around full-speed run/step commands.

## Why This Fork Exists

The upstream plugin starts an HTTP server inside x64dbg/x32dbg and exposes debugger operations such as memory reads, register reads, breakpoints, and debug control commands.

During reverse engineering work with x32dbg inside a Windows VM, two limitations became important:

1. The HTTP server was hard-bound to `127.0.0.1`, so macOS or another host on the LAN could not connect directly.
2. Synchronous `/Debug/Run` and `/Debug/Step*` requests could block the plugin HTTP server thread, making the bridge appear frozen after asking the debugger to run.

This fork addresses those two issues while preserving the original command style.

Historical design notes that are no longer on the main reading path now live in:

- `docs/archive/x64dbg_mcp_plugin_improvement_plan.md`

MusicBox15-specific helper scripts and breakpoint/label presets now live in:

- `x64dbg_tools/musicbox15/`

The former `x64dbg_tools/`-level MusicBox15 wrapper mirrors were retired after
active references converged on those canonical paths. Historical wrapper
transitions are tracked in `docs/repository_reorganization_audit.md`.

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
- Added wait-oriented debug endpoints so clients can stop scattering `sleep`
  loops:
  - `/Debug/WaitForBreak`
  - `/Debug/WaitForIdle`
- Added a breakpoint-specific wait endpoint:
  - `/Debug/WaitForBreakpointHit`

Operational rule for wait endpoints:

- use `WaitFor*` only for short, automation-controlled convergence after the
  client has already triggered the next debugger state
- do not use `WaitFor*` for phases that require a human to click buttons,
  load a sample, change UI state, or otherwise perform manual actions
- for user-driven phases, return control to the user first, then issue a fresh
  query or wait call only after the user reports the action is complete

Operational rule for breakpoint scenarios:

- treat multi-breakpoint experiment setups as script-layer workflows, not as a
  plugin-native profile system
- use the existing `/Breakpoint/*`, `/Log/BreakpointContext/*`, and `/Log/Clear`
  primitives plus target-specific `configure_*_logging.py` helpers to arm or
  clear a whole scene
- do not expand the plugin with `/Breakpoint/Profile/*` unless a concrete need
  appears that cannot be solved cleanly in the helper layer

Recommended breakpoint workflow:

1. Use helper scripts to arm exactly one focused scene.
2. If the next phase needs human GUI input, stop and return control to the user.
3. After the user confirms the action is complete, query logs or breakpoint
   state again.
4. Use `WaitForBreak`, `WaitForIdle`, or `WaitForBreakpointHit` only when the
   client has already triggered the next debugger state itself and only for
   short, automation-controlled waits.
- Added a debug action worker thread so async run/step requests return immediately.
- Added a plugin-side event buffer plus HTTP log endpoints so remote clients can read recent breakpoint/debug-string events without scraping the x64dbg GUI log window.
- Extended `/Log/Recent` with pagination metadata, `since`-based forward reads, and `limit=-1` full-buffer reads.
- Added configurable breakpoint-context expressions so callback events can include extra derived fields such as stack locals, registers, or decoded message-structure values.
- Expanded the software-breakpoint HTTP surface from basic set/delete helpers into a fuller configuration API:
  - `/Breakpoint/Get`
  - `/Breakpoint/Set`
  - `/Breakpoint/Delete`
  - `/Breakpoint/SetEnabled`
  - `/Breakpoint/SetName`
  - `/Breakpoint/SetCondition`
  - `/Breakpoint/SetLog`
  - `/Breakpoint/SetLogCondition`
  - `/Breakpoint/SetCommand`
  - `/Breakpoint/SetCommandCondition`
  - `/Breakpoint/SetFastResume`
  - `/Breakpoint/SetSingleshoot`
  - `/Breakpoint/SetSilent`
  - `/Breakpoint/GetHitCount`
- Extended breakpoint introspection so remote clients can read back `logCondition` and `commandCondition`, not just `breakCondition`, `logText`, and `commandText`.
- Added a plugin-verified `SetSilent` path so remote callers can request and verify the final silent state instead of relying on raw x64dbg command behavior.
- Added a Windows host-process execution surface:
  - `/Host/Spawn`
  - `/Host/Exec`
  - `/Host/Job/Get`
  - `/Host/Job/Kill`
- Added a minimal native file surface inside the plugin:
  - `/File/Stat`
  - `/File/Read`
  - `/File/Write`
  - `/File/Mkdir`
- Added Python-side bridge helpers for host execution and generic helper CLIs for:
  - host process invocation
  - message-capture initialization
  - raw event-log fetch
  - replay-oriented export
  - high-level replay of exported pointer/click action scripts
- Added a generic end-to-end message-capture workflow in `x64dbg_tools/`:
  - initialize capture breakpoints
  - fetch raw buffered events
  - export compressed replay-oriented actions
  - replay the exported actions locally or remotely
- Added bidirectional file-transfer helpers on top of `HostExec` and remote Python:
  - `push_file_via_hostexec.py` uploads local files to a Windows VM path in verified chunks
  - `pull_file_via_hostexec.py` downloads remote files back in verified chunks
- Prefer the native `/File/*` endpoints for simple stat/read/write/mkdir work.
  Keep the `HostExec` transfer helpers as the fallback path for larger or more
  specialized workflows.
- Added a socket receive timeout to avoid stalled client connections blocking the HTTP thread.
- Disabled the old synchronous `/Disasm/StepInWithDisasm` endpoint because it performed a direct step inside the HTTP request handler.
- Fixed HTTP server start/stop state handling to avoid a potential self-lock/restart issue.
- Fixed the `HostExec` client/server timeout mismatch so long-running successful jobs do not appear to fail just because the bridge-side HTTP read timeout was shorter than the requested host wait time.

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
http://<vm-ip>:8888/Health
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

- `breakpoint`: emitted from the official `CB_BREAKPOINT` plugin callback and includes breakpoint metadata such as address, hit count, conditions, configured log/command text, plus any caller-configured watched expressions when that feature is enabled.
- `output_debug_string`: emitted from `CB_OUTPUTDEBUGSTRING` when the debuggee calls `OutputDebugString`.

Read the newest buffered entries:

```text
/Log/Recent?limit=100
```

Read entries newer than a prior sequence id:

```text
/Log/Recent?since=250&limit=50
```

Read entries newer than a prior sequence id in forward-pagination order:

```text
/Log/Recent?since=250&limit=50&tail=false
```

Read every buffered entry newer than a prior sequence id:

```text
/Log/Recent?since=250&limit=-1
```

Read and clear in one request:

```text
/Log/Recent?limit=100&clear=true
```

Clear the buffer explicitly:

```text
/Log/Clear
```

`/Log/Recent` returns pagination metadata:

- `count`: number of returned entries
- `matchedCount`: number of buffered entries matching the `since` filter
- `totalBuffered`: current event-buffer size
- `hasMore`: whether more matching entries exist beyond the returned page
- `nextSince`: sequence id to reuse as the next `since` value
- `tail`: whether the request used newest-first truncation
- `unlimited`: whether `limit=-1` was used

### Recording While The Debuggee Keeps Running

The most important usage pattern for this event buffer is full-speed logging:
the target keeps running, x64dbg callback events keep accumulating, and the
remote side reads the whole buffer afterward.

The usual breakpoint shape for this is:

- `breakCondition = 1`
- `logText = ...`
- `commandText = $breakpointcondition=0`
- `commandCondition = ""`
- `silent = true`

Do not set `breakCondition = 0` for this pattern. If the break condition does
not evaluate true, x64dbg will not emit the breakpoint callback event, so the
plugin buffer will have nothing to record.

That combination means:

1. the breakpoint callback still fires
2. the event buffer still records the hit
3. x64dbg clears the final break decision before returning to the UI loop
4. the debuggee continues running without waiting for manual resume

In practice the workflow is:

1. Clear the old event buffer:

```text
/Log/Clear
```

2. Configure one or more auto-continue breakpoints.

3. Let the program run at full speed while the plugin accumulates events.

4. Read everything back at the end:

```text
/Log/Recent?since=0&limit=-1&tail=false
```

If you expect a long run, `limit=-1` is the safest readback form because it
does not truncate the result to a small tail window.

Optional watched expressions for breakpoint events can be configured at runtime.
The format is newline- or semicolon-separated `label=expression` pairs.

Example x86 `MSG*` context profile:

```text
/Log/BreakpointContext/Set?items=retaddr=[esp];msg_ptr=[esp+4];msg_hwnd=[[esp+4]];msg_message=[[esp+4]+4];msg_wparam=[[esp+4]+8];msg_lparam=[[esp+4]+0xC];msg_time=[[esp+4]+0x10];msg_x=[[[esp+4]+0x14]];msg_y=[[[esp+4]+0x14]+4]
```

List the currently configured expressions:

```text
/Log/BreakpointContext/List
```

Clear them and return to generic breakpoint events:

```text
/Log/BreakpointContext/Clear
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
      "text": "addr=0x76187809 type=normal hitCount=128 module=user32 breakCondition=1 logText=MSG_Translate msg_hwnd=0x001F02A2 msg_message=0x200"
    },
    {
      "seq": 42,
      "tickMs": 381910,
      "kind": "output_debug_string",
      "text": "example debug string captured from the target process"
    }
  ]
}
```

## Message Capture Workflow

This fork now includes a small end-to-end workflow for capturing GUI message
traffic, exporting it into a compact action script, and replaying the result.
All four scripts live directly in `x64dbg_tools/`:

- `init_message_capture.py`
- `fetch_message_capture.py`
- `export_message_replayish.py`
- `replay_message_replayish.py`
- `push_file_via_hostexec.py`
- `pull_file_via_hostexec.py`

The workflow is intentionally generic:

1. Initialize message-loop capture breakpoints in x64dbg.
2. Perform the target UI interaction manually.
3. Fetch the raw plugin event log to disk.
4. Export the raw log into a compact replay-oriented JSON/Markdown pair.
5. Replay the exported action script locally or through `HostExec`.

### 0. Find useful message-loop probe points

Do not hardcode message-loop addresses across runs. System DLLs are relocated,
and not every candidate API gives equally useful data.

The practical way to discover good probe points is:

1. Resolve the current addresses of message-loop candidates in the debugger for
   the current run.
   Good starting candidates are:
   - `TranslateMessage`
   - `PeekMessageW` / `PeekMessageA`
   - `GetMessageW` / `GetMessageA`
   - `DispatchMessageW` / `DispatchMessageA`
2. Attach temporary auto-continue breakpoints to those candidate entrypoints.
3. Configure a small watched-expression profile that tries to decode the
   candidate's key arguments, for example an x86 `MSG*` shape.
4. Perform one short UI gesture, such as a single click or a small mouse move.
5. Fetch the buffered events and compare the decoded output quality.

What usually makes a breakpoint "useful":

- the decoded pointer looks valid instead of `0`, `0xFEEEFEEE`, or code bytes
- `msg_message` values look like real Windows message ids
- `hwnd`, `x`, and `y` are plausible for the UI action you just performed
- the same breakpoint produces a stable shape over many hits

What usually makes a breakpoint "not useful":

- it decodes to garbage-looking fields
- the argument shape changes across callers
- it mostly reports internal framework churn rather than user-visible actions

In practice:

- `TranslateMessage` is often the best structured source for replay-oriented
  capture.
- `PeekMessageW` is often useful as a queue-side companion.
- `GetMessageW` matters mainly for programs that actually block on `GetMessage`
  rather than pumping with `PeekMessage`.
- `DispatchMessageW` should not be assumed to expose a single stable `MSG*`
  layout; verify it per caller family before trusting it as a structured source.
  If it does not decode cleanly, keep it only as a dispatch marker.

### 1. Initialize capture

`init_message_capture.py` configures breakpoint events and a default x86 `MSG*`
watched-expression profile. It expects the relevant addresses for your target
environment, because system DLLs are usually relocated at runtime.

The bundled default `--context-items` assume an x86 stack layout for
`TranslateMessage` / `PeekMessageW`-style entrypoints. For x64 targets, keep
the same breakpoint workflow but replace `--context-items` with an x64-appropriate
set of expressions.

Typical usage:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/init_message_capture.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --translate-addr 0x76187809 \
  --peek-addr 0x761905BA \
  --dispatch-addr 0x761872C4
```

This configures:

- `MSG_Translate` as the primary structured message source
- `MSG_PeekW` as an optional queue-side source
- `MSG_DispatchMarker` as an optional dispatch-family marker

All three breakpoints use the same auto-continue shape:

- `breakCondition = 1`
- `commandText = $breakpointcondition=0`
- `silent = true`

The helper intentionally configures these breakpoints one-by-one, waits briefly
after each mutation, and then polls the final breakpoint object until the
expected state is visible. In practice this is more reliable than trying to
blast several message-loop breakpoints into x64dbg at once and only checking
state afterward.

### 2. Record the raw event stream

After initialization, the intended recording pattern is:

1. clear the old plugin log
2. let the target run normally with the auto-continue breakpoints in place
3. perform the UI interaction manually
4. fetch the full buffered event log at the end

Example fetch step:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/fetch_message_capture.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --output-json tmp/message_capture_full.json \
  --output-breakpoints tmp/message_capture_breakpoints.json
```

By default this uses `limit=-1`, `since=0`, and forward pagination semantics,
so it retrieves the entire currently buffered log in one shot.

### 3. Export a compact replay-oriented script

Turn the raw `/Log/Recent` JSON into:

- a filtered event list
- a compressed `actions` list
- a Markdown summary

```text
python3 x64dbg_tools/export_message_replayish.py \
  tmp/message_capture_full.json \
  --output-prefix tmp/message_capture_export
```

The exporter keeps a small default message set:

- `WM_MOUSEMOVE`
- `WM_LBUTTONDOWN`
- `WM_LBUTTONUP`
- `WM_NCMOUSEMOVE`

It also compresses contiguous move runs into `move_segment` actions and removes
pure zero-displacement separators.

### 4. Replay the exported actions

Replay the exported `actions` list either in dry-run mode or for real:

```text
python3 x64dbg_tools/replay_message_replayish.py \
  tmp/message_capture_export.json \
  --dry-run
```

Live replay is currently Windows-only and uses high-level pointer primitives:

- `SetCursorPos`
- `mouse_event(MOUSEEVENTF_LEFTDOWN/LEFTUP)`

### 5. Replay remotely through HostExec

If the plugin is running on a Windows VM, the same exported action script can
be replayed through the bridge without opening a separate shell:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --cwd "C:\work\capture_demo" \
  --args "\"replay_message_replayish.py\" \"message_capture_export.json\" --dry-run" \
  --timeout-ms 20000
```

### 6. Push supporting files to the VM first

If the replay script or exported JSON are not already present on the Windows
side, `push_file_via_hostexec.py` can upload them through the same bridge by
splitting the local file into base64 chunks and letting remote Python rebuild
the destination file.

Push the replay script:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/push_file_via_hostexec.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --remote-python "<remote-python>" \
  x64dbg_tools/replay_message_replayish.py \
  "C:\work\capture_demo\replay_message_replayish.py"
```

Push the exported action JSON:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/push_file_via_hostexec.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --remote-python "<remote-python>" \
  tmp/message_capture_export.json \
  "C:\work\capture_demo\message_capture_export.json"
```

If the VM does not have a convenient Python entry point, use the PowerShell/.NET
variant instead:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/push_file_via_hostexec_powershell.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  local_file.bin \
  "C:\work\remote_file.bin"
```

On the current MusicBox VM, the confirmed Python path is:

```text
C:\Users\zyjsuper\AppData\Local\Programs\Python\Python314\python.exe
```

By default the helper verifies the remote file size and SHA-256 hash after the
last chunk is written.

Pull a generated file or log back from the VM:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/pull_file_via_hostexec.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --remote-python "<remote-python>" \
  "C:\work\capture_demo\message_capture_export.json" \
  tmp/message_capture_export.from_vm.json
```

## Host Process Execution

The plugin can now launch a Windows host-side process without going through
`cmd.exe`. This is intended for tightly scoped helper tasks such as replaying a
captured UI action script.

Available endpoints:

- `/Host/Spawn`
- `/Host/Exec`
- `/Host/Job/Get`
- `/Host/Job/Kill`

Common parameters:

- `program`: executable path on the Windows host
- `args`: raw command-line argument tail appended after the quoted program
- `cwd`: optional working directory

Client timeout behavior:

- `HostExec` waits on the plugin side for up to `timeoutMs`.
- The Python wrapper in `x64dbg_tools/x64dbg.py` now automatically keeps its
  HTTP read timeout longer than `timeoutMs`, so long-running successful jobs do
  not spuriously fail with a client-side read timeout first.

Start asynchronously:

```text
/Host/Spawn?program=<remote-python>&args=C:\work\scripts\replay_message_replayish.py%20C:\work\tmp\capture_export.json&cwd=C:\work
```

Execute and wait up to `timeoutMs`:

```text
/Host/Exec?program=<remote-python>&args=C:\work\scripts\replay_message_replayish.py%20C:\work\tmp\capture_export.json%20--dry-run&cwd=C:\work&timeoutMs=30000
```

Read job state:

```text
/Host/Job/Get?id=1
```

Terminate a running job:

```text
/Host/Job/Kill?id=1
```

Notes:

- `args` is treated as a raw command-line tail, so callers must quote any
  individual argument that contains spaces.
- stdout and stderr are currently merged into the returned `output` field.
- This is intentionally a host-process interface, not a shell interface.
- For larger artifacts such as scripts, JSON captures, or helper binaries,
  prefer `push_file_via_hostexec.py` instead of trying to inline the whole file
  content into a single command string.
- If the remote side generates files that you want to keep locally, prefer
  `pull_file_via_hostexec.py` instead of trying to print an entire file through
  one ad-hoc `python -c` command.

### Helper CLI

For bridge-driven usage, `x64dbg_tools/hostexec_call.py` is the easiest way to
invoke the host execution surface without writing ad-hoc `python -c` glue:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --args=-V \
  --timeout-ms 10000
```

### Remote File Upload Helper

`x64dbg_tools/push_file_via_hostexec.py` uses the existing `HostExec` API plus
remote Python to rebuild a file on the Windows side without manual copy/paste
or shared folders.

It works by:

1. reading the local source file
2. splitting it into chunks
3. base64-encoding each chunk
4. calling remote Python once per chunk to append it to the destination file
5. verifying remote size and SHA-256 by default

Typical usage:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/push_file_via_hostexec.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --remote-python "<remote-python>" \
  local_file.bin \
  "C:\work\remote_file.bin"
```

Useful options:

- `--cwd`: remote working directory for each host-exec call
- `--chunk-size`: raw bytes per upload chunk
- `--timeout-ms`: per-chunk host-exec timeout
- `--no-verify`: skip remote size/hash verification

### Remote File Upload Helper (PowerShell/.NET)

`x64dbg_tools/push_file_via_hostexec_powershell.py` provides the same upload
surface without requiring remote Python. It uses:

1. `HostExec` with Windows PowerShell
2. base64 chunks
3. `[IO.File]::WriteAllBytes(...)` for the first chunk
4. a .NET `FileStream` append path for follow-up chunks
5. `SHA256Managed` for remote verification

Typical usage:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/push_file_via_hostexec_powershell.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  local_file.bin \
  "C:\work\remote_file.bin"
```

### Remote File Download Helper

`x64dbg_tools/pull_file_via_hostexec.py` is the inverse helper. It asks remote
Python for file metadata first, then reads the target file back in chunks and
reassembles it locally.

It works by:

1. calling remote Python to query `exists`, `size`, and `sha256`
2. reading the remote file back chunk-by-chunk as base64
3. rebuilding the file locally
4. comparing the rebuilt local size/hash against the remote metadata by default

Typical usage:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/pull_file_via_hostexec.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --remote-python "<remote-python>" \
  "C:\work\remote_file.bin" \
  local_copy.bin
```

Useful options:

- `--cwd`: remote working directory for each host-exec call
- `--chunk-size`: raw bytes per download chunk
- `--timeout-ms`: per-chunk host-exec timeout
- `--no-verify`: skip final local-vs-remote size/hash verification

### Remote Python Examples

Check the remote Python interpreter version:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --args=-V \
  --timeout-ms 10000
```

Run a short one-liner on the Windows host:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --args="-c \"print('hello from host python')\"" \
  --timeout-ms 10000
```

Run a Python script from a working directory:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --cwd "C:\work\capture_demo" \
  --args "\"replay_message_replayish.py\" \"message_capture_export.json\" --dry-run" \
  --timeout-ms 20000
```

Run the same script for real replay:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --program "<remote-python>" \
  --cwd "C:\work\capture_demo" \
  --args "\"replay_message_replayish.py\" \"message_capture_export.json\"" \
  --timeout-ms 30000
```

Run asynchronously and inspect later:

```text
rtk x64dbgvenv/bin/python x64dbg_tools/hostexec_call.py \
  --x64dbg-url http://<vm-ip>:8888/ \
  --mode spawn \
  --program "<remote-python>" \
  --cwd "C:\work\capture_demo" \
  --args "\"replay_message_replayish.py\" \"message_capture_export.json\""
```

## Legacy Breakpoint Action Caveats

This fork still exposes the older breakpoint-management surface through x64dbg commands and `/Breakpoint/List`, but real-world tracing showed that the legacy GUI breakpoint action workflow is not a reliable source of truth for remote automation.

Observed problems during real-world reverse-engineering and GUI automation work:

- `Breakpoint/List` only reports the configured breakpoint fields such as `breakCondition`, `logText`, and `commandText`. It does not prove that x64dbg actually evaluated those fields the way the GUI suggests at runtime.
- `Breakpoint/List` now also returns `logCondition` and `commandCondition`, which helps explain GUI states where those condition fields remain populated even after the corresponding command or log text has been cleared.
- Complex breakpoint conditions could be present in `Breakpoint/List` and still behave inconsistently at execution time.
- This fork does not re-evaluate breakpoint conditions inside the plugin. It records the `BRIDGEBP` fields returned by x64dbg and the later `CB_BREAKPOINT` callback that x64dbg emits. If those two disagree, the mismatch is in the underlying x64dbg breakpoint/action behavior, not in the plugin's event buffer.
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

### Software Breakpoint Read/Write Endpoints

To reduce reliance on raw `ExecCommand`, this fork now exposes a software-breakpoint endpoint family that mirrors the official x64dbg manual commands for software breakpoints:

```text
/Breakpoint/Get?addr=0x004C223B
/Breakpoint/Set?addr=0x004C223B
/Breakpoint/Delete?addr=0x004C223B
/Breakpoint/SetEnabled?addr=0x004C223B&enabled=true
/Breakpoint/SetName?addr=0x004C223B&name=trace_probe
/Breakpoint/SetCondition?addr=0x004C223B&condition=cip==0x004C223B
/Breakpoint/SetLog?addr=0x004C223B&text=trace_hit
/Breakpoint/SetLogCondition?addr=0x004C223B&condition=eax==0x42
/Breakpoint/SetCommand?addr=0x004C223B&text=pause
/Breakpoint/SetCommandCondition?addr=0x004C223B&condition=eax==0x42
/Breakpoint/SetFastResume?addr=0x004C223B&enabled=true
/Breakpoint/SetSingleshoot?addr=0x004C223B&enabled=true
/Breakpoint/SetSilent?addr=0x004C223B&silent=true
/Breakpoint/GetHitCount?addr=0x004C223B
```

These endpoints intentionally stay close to the official command set:

- `SetBreakpointName`
- `SetBreakpointCondition`
- `SetBreakpointLog`
- `SetBreakpointLogCondition`
- `SetBreakpointCommand`
- `SetBreakpointCommandCondition`
- `SetBreakpointFastResume`
- `SetBreakpointSingleshoot`
- `SetBreakpointSilent`

The plugin still delegates the actual mutation to x64dbg's own breakpoint commands, but the bridge now:

- gives you a structured readback path through `/Breakpoint/Get` and `/Breakpoint/List`
- exposes `logCondition` and `commandCondition` in JSON
- returns the post-command breakpoint object so bridge-side automation can inspect what x64dbg actually stored

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
http://<vm-ip>:8888/Debug/RunAsync
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
- LAN endpoint: `http://<vm-ip>:8888/`.

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
    - `x64dbgvenv/bin/python x64dbg.py RegisterGet --x64dbg-url http://<vm-ip>:8888/ eax`
    - `x64dbgvenv/bin/python x64dbg.py DebugSetBreakpoint --x64dbg-url http://<vm-ip>:8888/ 0x004C231C`
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
X64DBG_URL=http://<vm-ip>:8888/ x64dbgvenv/bin/python x64dbg.py
```

Examples with positional tool arguments:

```bash
x64dbgvenv/bin/python x64dbg.py RegisterGet --x64dbg-url http://<vm-ip>:8888/ eax
x64dbgvenv/bin/python x64dbg.py MiscParseExpression --x64dbg-url http://<vm-ip>:8888/ "[ebp-0x2c]"
x64dbgvenv/bin/python x64dbg.py GetRegisterDump --x64dbg-url http://<vm-ip>:8888/
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
