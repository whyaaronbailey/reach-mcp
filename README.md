# Reach MCP

**PC control for ChatGPT and Claude chats**

An open-source Windows desktop-control server for MCP clients. It provides screenshots, mouse and keyboard input, window focus, clipboard access, and application launch through stdio or authenticated loopback HTTP. An optional GitHub OAuth relay connects remote clients such as ordinary ChatGPT Chat. ChatGPT has been tested end to end; the Claude Chat OAuth callback is supported but has not yet been verified in a live Claude Chat session.

The server is designed for a dedicated Windows VM. Desktop control runs with the logged-in user's privileges; it is not a sandbox.

## Approval controls

The local control panel offers three modes:

| Mode | Behavior |
| --- | --- |
| Ask for approval (default) | Each desktop tool call waits for a local approval. Reads require approval too. |
| Approve for me | Automatically allows a small, fixed set of observation tools; clipboard reads and actions still require approval. |
| Full access | Bypasses the approval queue for the selected time window. Other safety checks remain active. |

These controls are enforced by the native server, independently of the MCP client's permission setting. “Low risk” means an explicit tool allowlist, not AI judgment of an action's intent. Screenshots and window information can still contain private data.

The server starts in Ask mode. Temporary modes expire back to Ask; changing modes cancels pending requests. Open the panel from the Windows desktop after starting a server:

```powershell
.\scripts\open-controls.ps1
```

The panel and its private URL are local-only. Do not expose its port, share its URL, or add it to the public relay. A client may also ask for approval, so both prompts can apply. See [SECURITY.md](SECURITY.md) for the limits of a panel running on the controlled desktop.

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

Start a stdio server:

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

## Safety and configuration

Copy `config.example.toml` to `config.toml` to change limits, disable tools, or restrict application launch.

A source checkout keeps configuration, audit logs, pause state, and private panel state in the project directory. An installed wheel uses `%LOCALAPPDATA%\ReachMCP` instead. Set `REACH_MCP_HOME` before starting the server to choose a different writable private directory. Relative configuration paths resolve from that directory.

- Move the mouse to the top-left corner or run `scripts\pause.ps1` to block input. Run `scripts\resume.ps1` to remove the file-based pause. These input kill switches do not block reads.
- `logs\audit.jsonl` records tool calls. Typed and clipboard text arguments are redacted by default.
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
