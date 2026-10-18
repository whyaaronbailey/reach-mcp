# Remote OAuth relay

The optional relay exposes the desktop tools to remote MCP clients, including ordinary ChatGPT Chat. It uses GitHub OAuth with one configured immutable numeric owner ID and forwards requests to the bearer-protected native server. Both processes listen only on loopback.

The public endpoint is `https://<your-public-host>/mcp`. Never publish the native server or the approval panel.

## Setup

From the project directory, as the normal logged-in Windows user:

```powershell
.\scripts\setup.ps1
.\web\setup.ps1
```

This creates separate native and relay virtual environments. The relay's FastMCP dependency is isolated from the native MCP SDK.

Create a GitHub OAuth App. Set its homepage to your public HTTPS origin and its callback to that origin plus `/auth/callback`. Obtain your own immutable numeric GitHub user ID from GitHub's user API. Do not use a username for the owner lock.

Configure credentials locally, replacing both example values:

```powershell
.\web\configure-github.ps1 `
    -PublicUrl 'https://your-device.your-tailnet.ts.net' `
    -OwnerGitHubUserId 12345678
```

The client-secret prompt is masked. Never paste secrets into a chat, shell command argument, issue, or log. The script calls `setup-secrets.ps1`, generates local signing and bearer keys if absent, and restricts the secrets folder to the owner, SYSTEM, and Administrators.

Private files, excluded from Git:

- `web\secrets\github-oauth.json`: OAuth credentials, local keys, public origin, loopback native URL, and one owner ID.
- `web\secrets\deployment.json`: pins the machine name, public origin, native URL, and owner ID to this installation.

For credential rotation, run `configure-github.ps1` again. Existing origin, owner, and local keys are preserved unless explicitly supplied. A new machine must be configured locally; do not copy live private state into a published repository.

Default listeners:

| Service | Address |
| --- | --- |
| Native MCP | `127.0.0.1:8765/mcp` |
| Owner approval panel | `127.0.0.1:8766` |
| OAuth relay | `127.0.0.1:8891` |
| Isolated native test server | `127.0.0.1:18765` |
| Relay integration test | `127.0.0.1:8899` |

The native port can be changed with `-NativePort` during configuration; use a distinct available port. The relay and panel ports remain local-only.

## Run and verify locally

```powershell
.\web\run-web.ps1
```

The runner refuses elevation and mismatched deployment identity. A Windows job object keeps the runner and its children together; stopping the runner closes both servers. It also exits if either child fails.

Open the approval controls from another local shell:

```powershell
.\scripts\open-controls.ps1
```

The native server starts in Ask mode. Approve pending calls locally, or choose a temporary mode for a task you have authorized. The relay has no API to change approval modes.

Unit checks do not publish anything:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\web\.venv\Scripts\python.exe web\test_owner.py -q
```

Run the isolated integration test deliberately from a non-elevated interactive desktop:

~~~powershell
.\.venv\Scripts\python.exe web\check-local.py
~~~

The wrapper creates fresh dummy credentials, a temporary native listener on port 18765, and an ephemeral local approval panel. It explicitly selects low-risk mode for its own observation calls through the normal owner API, then runs the relay tests on port 8899. It does not read production credentials or change the running deployment. Its Windows job removes test child processes and their descendants on exit. The test reads screen information and captures a screenshot.

To test a specific already-running native server, run the relay environment's Python with `web/test_relay.py --config <local-json-path>`. Such a server still needs its own approvals. Dummy-credential checks do not prove a real GitHub login or external connectivity.

## Publish deliberately

Only publish a deployment you intend to make reachable. Configure Tailscale on the target VM and verify that its public hostname matches the GitHub callback and configured origin.

To expose only the OAuth relay with Tailscale Funnel:

```powershell
tailscale funnel --bg --https=443 http://127.0.0.1:8891
```

Verify from a separate network that unauthenticated MCP requests return 401, unknown methods/tools return 403, and OAuth discovery reports the configured public origin. Then complete a real owner sign-in. Unit tests with mocked GitHub responses cannot replace this step.

If you want startup at login, register an interactive, non-elevated scheduled task for `web\run-web.ps1`. Use the desktop user's account, Limited privileges, and no execution time limit. Do not run the desktop server as SYSTEM or as an administrator. A logged-in interactive desktop is required.

## Connect a remote client

In ChatGPT, add a custom MCP server with the public `/mcp` URL and OAuth authentication. Complete GitHub sign-in as the configured owner. In the plugin's permissions, use Always ask if you also want client-side prompts before reads and changes. Product labels and availability can change.

A client approval and a native-server approval are separate checks. OAuth proves the owner identity; it is not a per-action consent grant. An ordinary Chat connection does not establish or guarantee any provider's billing or usage accounting.

## A tool is discovered but its call fails after a minute

Ask mode also requires a decision in the local owner panel. Client-side consent
(such as ChatGPT's Allow once) does not grant native-server approval. A pending
call expires after 60 seconds if no local decision arrives; the desktop handler
does not run.

Open scripts\open-controls.ps1 on the VM, retry the tool call, and approve that
pending call with Allow once before it expires. Expired calls must be retried.
Keep Ask selected unless you deliberately authorize a temporary automatic mode.
Expected approval failures return an actionable message. Unexpected handler
failures stay masked remotely; inspect private logs\audit.jsonl and
web\server-stderr.log for their cause.

## Disable or revoke

Input pause:

```powershell
.\scripts\pause.ps1
```

This blocks input, not observation. Remove public exposure separately:

```powershell
tailscale funnel --https=443 off
```

Stop the runner. If you created the example startup task:

```powershell
Disable-ScheduledTask -TaskName 'Reach MCP Web Relay'
Stop-ScheduledTask -TaskName 'Reach MCP Web Relay'
```

Verify the native and relay listeners have closed. Persistent Funnel configuration is independent of process lifetime. Power off or firewall the VM for a separate boundary. Revoke OAuth authorization and rotate credentials when appropriate.

Private deployment history and evidence are kept under ignored `local-deployment\` and `logs\`, never in the public documentation.
