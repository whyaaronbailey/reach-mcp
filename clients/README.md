# MCP clients

Use the executable in this checkout's virtual environment:

```text
C:\Path\To\reach-mcp\.venv\Scripts\reach-mcp.exe
```

Configure a stdio MCP server in your client with that executable, arguments `["--client", "your-client-name"]`, and the project directory as its working directory. The client name labels audit entries; it is not an authenticated identity.

For example, a Codex configuration can use:

```toml
[mcp_servers.reach]
command = 'C:\Path\To\reach-mcp\.venv\Scripts\reach-mcp.exe'
args = ["--client", "codex"]
startup_timeout_sec = 20
```

Replace the example path with your checkout. Keep the client's own approval setting enabled, then open this server's local controls with `scripts\open-controls.ps1`. Native approval enforcement applies regardless of the client's permission policy. Remove the client entry to unregister the server.

## Loopback HTTP

```powershell
$env:REACH_MCP_TOKEN = & .\scripts\new-token.ps1
.\scripts\run-http.ps1
```

Connect locally to `http://127.0.0.1:8765/mcp` with an `Authorization: Bearer <token>` header. Store the token in the client's secret mechanism, not source control or a chat.

## Remote Chat

A cloud-hosted Chat cannot launch this local stdio server or reach your loopback interface. Use the separately authenticated [OAuth relay](../web/README.md). Do not publish the native HTTP endpoint or the approval panel.

Local desktop plugin packaging is not part of this distribution. Clients' menus and configuration formats may change; use their current documentation when registering a server.
