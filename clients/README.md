# MCP clients

Use the executable in this checkout's virtual environment:

```text
C:\Path\To\reach-mcp\.venv\Scripts\reach-mcp.exe
```

Configure a stdio MCP server in your client with that executable, arguments `["--client", "your-client-name", "--approval-policy", "client"]` for consent managed by the client, and the project directory as its working directory. The client name labels audit entries; it is not an authenticated identity.

For example, a Codex configuration can use:

```toml
[mcp_servers.reach]
command = 'C:\Path\To\reach-mcp\.venv\Scripts\reach-mcp.exe'
args = ["--client", "codex", "--approval-policy", "client"]
startup_timeout_sec = 20
```

Replace the example path with your checkout. Keep the client's own approval setting enabled. With `--approval-policy client`, there is no additional local prompt; Reach MCP trusts the client to obtain consent and cannot verify a human's chat approval. For a separate local approval layer, omit the option or set it to `local`, then open `scripts\open-controls.ps1` and approve requests there. Local policy starts in Ask mode. Remove the client entry to unregister the server.

## Loopback HTTP

```powershell
$env:REACH_MCP_TOKEN = & .\scripts\new-token.ps1
.\.venv\Scripts\reach-mcp.exe --transport http --client http --approval-policy client
```

Connect locally to `http://127.0.0.1:8765/mcp` with an `Authorization: Bearer <token>` header. Store the token in the client's secret mechanism, not source control or a chat. This example uses client-managed consent; omit `--approval-policy client` for local Ask mode.

## Remote Chat

A cloud-hosted Chat cannot launch this local stdio server or reach your loopback interface. Use the separately authenticated [OAuth relay](../web/README.md). Do not publish the native HTTP endpoint or the approval panel. Start the relay with `web\run-web.ps1 -ApprovalPolicy client` and select **Always ask** in the ChatGPT plugin's permissions for consent only in the chat. Keep the startup parameter in any scheduled task. Other clients must provide and enforce their own permission controls.

Local desktop plugin packaging is not part of this distribution. Clients' menus and configuration formats may change; use their current documentation when registering a server.
