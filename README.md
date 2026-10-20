# Reach MCP

**PC control for ChatGPT and Claude chats**

An open-source Windows control server for MCP clients. Its 30 tools combine screenshots, mouse and keyboard input with direct file access, code search, exact patches, and managed terminal jobs through stdio or authenticated loopback HTTP. An optional GitHub OAuth relay connects remote clients such as ordinary ChatGPT Chat. ChatGPT has been tested end to end; the Claude Chat OAuth callback is supported but has not yet been verified in a live Claude Chat session.

The server is designed for a dedicated Windows VM. Desktop control runs with the logged-in user's privileges; it is not a sandbox.

## Approval controls

Choose where approvals happen when starting the server:

| Policy | Behavior |
| --- | --- |
| `client` | The connected MCP client's permission settings govern consent. No local approval prompt or queue is used. |
| `local` (default) | The native server requires decisions in its local control panel, independently of any client prompts. |

For remote Chat use with approvals only in the chat, start the relay with:

```powershell
.\web\run-web.ps1 -ApprovalPolicy client
```

In ChatGPT, select **Always ask** in the Reach MCP plugin's permissions. You can then approve tool requests from the chat without being at the VM. Other clients must provide and enforce their own permission controls. Keep `-ApprovalPolicy client` in the startup task's command if you want this choice to survive restarts.

Client policy trusts the connected client to obtain consent. MCP does not provide Reach MCP with cryptographic proof that a human approved each call, so the server cannot verify the chat's permission prompt. OAuth owner authentication, native HTTP bearer authentication, loopback listeners, disabled-tool rules, audit logging, and input kill switches still apply. See [SECURITY.md](SECURITY.md).

For an additional local decision, use `local` policy and open the controls from the Windows desktop:

```powershell
.\scripts\open-controls.ps1
```

The local control panel offers three modes:

| Mode | Behavior under local policy |
| --- | --- |
| Ask for approval (startup default) | Each desktop tool call waits for a local approval. Reads require approval too. |
| Approve for me | Automatically allows a small, fixed set of observation tools; clipboard reads and actions still require approval. |
| Full access | Bypasses the local approval queue for the selected time window. Other safety checks remain active. |

Temporary local modes expire back to Ask; changing modes cancels pending requests. “Low risk” means an explicit tool allowlist, not AI judgment of an action's intent. Screenshots and window information can still contain private data. Client policy is a separate startup policy, not a temporary Full access mode.

The panel and its private URL are local-only. Do not expose its port, share its URL, or add it to the public relay. With local policy, both client and local prompts can apply.

## Requirements and setup

- Windows 10 or 11 with an interactive desktop
- Python 3.12
- A normal, non-administrator user account

Clone the project, then run setup:

```powershell
git clone https://github.com/whyaaronbailey/reach-mcp.git
cd reach-mcp
```

From the project directory:

```powershell
.\scripts\setup.ps1
# Or supply a Python executable:
.\scripts\setup.ps1 -Python 'C:\Path\To\Python312\python.exe'
```

Setup creates `.venv`, installs the project and development dependencies, and runs the unit tests. It does not register an MCP client, publish a network endpoint, or create a startup task.

Start a stdio server with the default local approval policy:

```powershell
.\.venv\Scripts\reach-mcp.exe --client local
```

See [clients/README.md](clients/README.md) for client registration and loopback HTTP. For remote Chat, follow [web/README.md](web/README.md).

## Tools

| Tool | Purpose |
| --- | --- |
| `reach_get_screen_info` | Monitor layout, cursor, foreground window, capture and safety state |
| `reach_screenshot` | Capture a monitor, window, region, or all monitors |
| `reach_list_windows` | Visible top-level windows and their rectangles |
| `reach_get_cursor_position` | Cursor coordinates |
| `reach_get_clipboard` / `reach_set_clipboard` | Read or write clipboard text |
| `reach_wait` | Wait briefly, optionally capture a screenshot |
| `reach_focus_window` | Restore and focus a window |
| `reach_move_mouse`, `reach_click`, `reach_drag`, `reach_scroll` | Mouse input |
| `reach_type_text` | Unicode text input |
| `reach_press_keys` | Keys and chords, such as `ctrl+s` |
| `reach_launch_application` | Open a program, file, or URL |

Action tools can return a fresh screenshot with `screenshot: true`. Coordinates default to the most recent screenshot's pixel space; the server maps the downscaled image to physical pixels. Use `coordinate_space: "screen"` for raw desktop coordinates. Capture again after the target moves. Coordinate actions waiting for approval reject a changed screenshot mapping.

Unicode input uses conservative pacing for Windows text controls and checks input kill switches between characters. The default limit is 500 characters per call; use an explicitly approved clipboard paste for longer text. Verify the resulting text in the target application.

UI Automation element snapshots and actions are **not implemented**. The current tool surface uses screenshots and Windows input APIs. The proposed UIA-first/screenshot-fallback design remains a roadmap item.

## Files and terminal

Call `reach_get_capabilities` for this installation's workspace, local roots and limits.
The default file roots are the project/state folder and current user's home.

| Tools | Purpose |
| --- | --- |
| `reach_list_directory`, `reach_search_files` | Bounded directory, filename and literal text search |
| `reach_read_file` | Text, line pagination and full-file SHA256 |
| `reach_write_file`, `reach_replace_text`, `reach_apply_patch` | Create text, exact replacements or unified diffs |
| `reach_make_directory`, `reach_move_file`, `reach_remove_file` | Directories, moves and non-recursive deletion |
| `reach_run_command` | PowerShell, cmd or exact argv; cwd, output and exit code |
| `reach_read_process`, `reach_write_process` | Poll output/status and send stdin |
| `reach_list_processes`, `reach_cancel_process` | Inspect retained jobs and stop a process tree |

Read an existing file first, then pass its SHA256 to edits, moves and deletion.
Changed files are rejected instead of overwritten. New files require `create: true`.
UTF-8 and BOM-marked UTF-16 are supported. Replacements and patches preserve BOM/newlines.
Patches use standard unified `---`, `+++` and `@@` headers,
with an `expected_sha256` path-to-hash map (null for new files).
Multi-file patches validate all hunks and attempt rollback on I/O failure; they
are not an OS-level transaction. Recursive deletion, shares, device paths,
symlinks and junctions are refused by the file tools.

For commands, specify `cwd` and optionally `shell: "program"` with an argv array.
Save `job_id`, poll using `next_cursor`, and inspect `exit_code`,
`output_complete`, `has_more` and truncation flags.
Jobs have runtime, count and retained-output limits. Commands and descendants are
terminated on cancellation, timeout, pause, server shutdown or parent exit.
Failed or cancelled commands can leave file changes; inspect before retrying.

Commands run as the normal Windows user and can access that user's files and
network beyond the first-class file roots: this is **not a shell sandbox**.
Credential-like environment variables are removed from children; credential files
remain subject to Windows account permissions. File/terminal tools work while
Windows is locked; desktop input and screenshots still need an interactive session.

Reach does not call an AI model to execute these tools. See [Usage audit](docs/usage.md)
for Chat versus Work/Codex accounting and an isolated verification procedure.

## Safety and configuration

Copy `config.example.toml` to `config.toml` to change limits, disable tools, or restrict application launch.

A source checkout keeps configuration, audit logs, pause state, and private panel state in the project directory. An installed wheel uses `%LOCALAPPDATA%\ReachMCP` instead. Set `REACH_MCP_HOME` before starting the server to choose a different writable private directory. Relative configuration paths resolve from that directory.

- Move the mouse to the top-left corner or run `scripts\pause.ps1` to block desktop input, file mutations and new commands, and stop active managed jobs. Run `scripts\resume.ps1` to remove the file-based pause. These input kill switches do not block reads.
- `logs\audit.jsonl` records tool calls. Typed and clipboard text arguments are redacted by default. Developer payloads, paths, commands and stdin are always redacted; file contents and command output are never audit logged. Each call has a unique event ID.
- Native HTTP binds only to loopback and requires a bearer token. Never expose that listener directly.
- The OAuth relay admits exactly one configured immutable GitHub user ID and exposes a fixed tool allowlist.
- Run without elevation. UAC, the lock screen, and higher-integrity windows are outside the supported desktop.
- Power off or firewall the VM to remove access independently of this software.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\smoke_test.py
.\.venv\Scripts\python.exe scripts\smoke_test.py --interactive
```

Smoke tests access the actual desktop and require approval. They start a separate temporary server in Ask mode. For a deliberate unattended test, add `--approve-test-calls` to authorize only that isolated server for 300 seconds through its normal owner API; this does not change a running deployment. The interactive test opens a unique Notepad document, verifies Unicode input, restores the clipboard when the connection remains available, and closes its test document. Run it on a disposable desktop with no sensitive clipboard contents.

See [STATUS.md](STATUS.md) for implementation status and [CONTRIBUTING.md](CONTRIBUTING.md) for development.

## License

MIT. See [LICENSE](LICENSE). Dependency licenses remain with their respective projects.
