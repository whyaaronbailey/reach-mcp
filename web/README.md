# Remote OAuth relay

The optional relay exposes the desktop, file and terminal tools to remote MCP clients, including ordinary ChatGPT Chat. It uses GitHub OAuth with one configured immutable numeric owner ID and forwards requests to the bearer-protected native server. Both processes listen only on loopback.

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

For approvals only in your trusted chat client:

```powershell
.\web\run-web.ps1 -ApprovalPolicy client
```

The runner refuses elevation and mismatched deployment identity. A Windows job object keeps the runner and its children together; stopping the runner closes both servers. It also exits if either child fails.

Select **Always ask** in the ChatGPT plugin's permissions before using the tools. With client policy, requests run after the connected client sends them; there is no additional VM approval queue. You can use the chat remotely without opening the VM controls.

Client policy trusts the authenticated client to enforce consent. The native MCP server receives no cryptographic evidence of a human's approval in the chat. Owner authentication is not per-call consent. Other clients must supply their own permission controls.

For an additional local approval layer, run `web\run-web.ps1 -ApprovalPolicy local` (also the default when the parameter is omitted). That policy starts in Ask mode. Open `scripts\open-controls.ps1` on the VM to approve pending calls or choose a temporary local mode. The relay cannot change the startup policy through an MCP tool. Both policies retain owner authentication, bearer protection, loopback listeners, disabled-tool rules, audit logging, and input kill switches.

Unit checks do not publish anything:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\web\.venv\Scripts\python.exe web\test_owner.py -q
```

Run the isolated integration test deliberately from a non-elevated interactive desktop:

~~~powershell
.\.venv\Scripts\python.exe web\check-local.py
~~~

The wrapper creates fresh dummy credentials, a temporary native listener on port 18765, and an ephemeral local approval panel. It explicitly selects temporary Full access only on its isolated test server for its own desktop/developer calls through the normal owner API, then runs the relay tests on port 8899. It does not read production credentials or change the running deployment. Its Windows job removes test child processes and their descendants on exit. The test reads screen information, captures a screenshot, lists a directory, and runs an echo command on the isolated child.

To test a specific already-running native server, run the relay environment's Python with `web/test_relay.py --config <local-json-path>`. A server using local policy still needs its own local approvals; client policy has no local approval queue. Dummy-credential checks do not prove a real GitHub login or external connectivity.

## Publish deliberately

Only publish a deployment you intend to make reachable. Configure Tailscale on the target VM and verify that its public hostname matches the GitHub callback and configured origin.

To expose only the OAuth relay with Tailscale Funnel:

```powershell
tailscale funnel --bg --https=443 http://127.0.0.1:8891
```

Verify from a separate network that unauthenticated MCP requests return 401, unknown methods/tools return 403, and OAuth discovery reports the configured public origin. Then complete a real owner sign-in. Unit tests with mocked GitHub responses cannot replace this step.

If you want startup at login, register an interactive, non-elevated scheduled task for `web\run-web.ps1`. Use the desktop user's account, Limited privileges, and no execution time limit. Do not run the desktop server as SYSTEM or as an administrator. A logged-in interactive desktop is required. Include `-ApprovalPolicy client` in the task's runner arguments for chat-only consent after a restart; omitting it selects local policy and starts in Ask mode.

## Connect a remote client

In ChatGPT, add a custom MCP server with the public `/mcp` URL and OAuth authentication. Complete GitHub sign-in as the configured owner. In the plugin's permissions, select **Always ask** for prompts before reads and changes. Run the server with `-ApprovalPolicy client` for approvals only in the chat. Product labels and availability can change.

Under local policy, a client approval and a native-server approval are separate checks. Under client policy, consent is delegated to the client. OAuth proves the owner identity; it is not a per-action consent grant. OpenAI documents ordinary Chat allowances separately from Work/Codex; Reach does not make model calls. Verify the actual client surface and isolated usage readings using [the usage audit](../docs/usage.md). A connection alone does not prove billing attribution.

## A tool is discovered but its call fails after a minute

A local-approval timeout means the native server is using local policy. Its pending call expired after 60 seconds without a local decision; the desktop handler did not run. Empty arguments are valid for `reach_get_screen_info`.

If you want approvals only in the chat, stop the runner and restart it with `-ApprovalPolicy client`, then retry. Retain that parameter in any startup task and keep the client's permission controls enabled. A server already running under local policy must be restarted to change its startup policy.

If you deliberately selected local policy, open `scripts\open-controls.ps1` on the VM, retry the tool call, and approve the new pending call before it expires. Expired calls must be retried.

Expected approval failures return an actionable message. Unexpected handler failures stay masked remotely; inspect private `logs\audit.jsonl` and `web\server-stderr.log` for their cause.

## A launch succeeds but typing fails or Windows is locked

Application launch does not prove that the interactive Windows desktop is available.
A locked session, a disconnected session, or a secure Windows prompt can prevent
normal desktop input. Opening local approval controls does not resolve this state.

Version 0.2.3 reports `approval_policy` and `desktop` availability in
`reach_get_screen_info`. Screen information remains readable when the cursor cannot
be queried. Input calls check session availability before dispatch; known desktop
access failures return a safe, actionable message through the relay.

A typing call interrupted by a desktop change may already have entered some text.
Restore an unlocked Windows session and inspect the target before retrying.
Reach MCP does not unlock Windows, enter credentials, disable locking, or bypass UAC.
For unattended use, the owner must deliberately arrange an available interactive
session on the dedicated VM. Client-managed approval does not bypass Windows login.

Native instructions reflect the selected startup approval policy. Relay instructions
tell clients to distinguish desktop availability from local approval failures.
Existing clients may need a new connection or refreshed catalog to pick up instructions.

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

## Upgrading to the developer tool set

Version 0.3.0 explicitly allowlists 30 tools. Restart both native server and relay
after updating, then refresh the client's Reach tool catalog. Existing OAuth owner
authentication and the selected approval policy remain required. Review permissions
for the new write/delete/command tools in the client; under client policy no local
VM prompt is added.

Call reach_get_capabilities to inspect roots and limits, then test a disposable
file and a read-only terminal command. The default local file roots are the project
folder and current user's home. Configure filesystem and execution in config.toml;
setting enabled=false hides the corresponding tool group.

The terminal runs as the normal server user with file/network access, beyond the
first-class file roots. PAUSED/corner stop active managed commands and block new
mutations, while read/status/cancel calls remain available. To disable the expanded
capabilities, disable both config sections and restart. To remove all remote access,
stop the runner/task and turn off this VM's Funnel as described below.

Do not retain an older computer's public endpoint after migrating a deployment.
Turn off its previous Funnel route and disable its old relay startup task locally.
Machine-specific commands and evidence belong in ignored local deployment records.
