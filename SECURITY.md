# Security model

This project exposes the privileges of a Windows desktop user. A model that can send keyboard and mouse input can open a terminal, modify files, access signed-in applications, and send data. Tool approvals reduce accidental or unintended use; they do not contain a malicious client.

## Boundaries

- Use a dedicated VM and a non-administrator account.
- The native server and approval panel listen on loopback. The native HTTP endpoint requires its own bearer token.
- The optional public relay requires GitHub OAuth and exactly one immutable numeric owner ID. OAuth authenticates the owner; it does not prove approval for each action or identify an individual chat.
- The relay exposes only the explicitly listed desktop and developer tools. The approval panel is never proxied.
- The default `local` approval policy starts in Ask mode. Temporary automatic modes expire. The low-risk mode uses a documented observation allowlist, not a semantic risk classifier.
- Under local policy, approval decisions apply to the pending call and arguments. They are not a general grant to a conversation.
- Explicit `client` approval policy delegates consent to the connected MCP client and has no local queue. For chat-only consent, select the client's permission controls, such as ChatGPT's Always ask. Native MCP does not supply cryptographic proof that a human approved a call, so Reach MCP cannot verify those prompts. Only use this policy with a trusted client that enforces the permissions you intend.
- Client policy is selected in the startup command, persists only when that command retains the option, and cannot be chosen by an MCP tool. It is separate from temporary local Full access mode. Authentication, loopback restrictions, disabled-tool rules, input kill switches, and auditing remain active under both policies.

The control panel is on the same desktop the agent controls. A client with sufficient input access may be able to interact with it, read local state, or alter this application's files. Loopback tokens and file ACLs do not isolate processes running as the same Windows user. Client policy permits approvals in a separate trusted chat client without visiting the controlled desktop, but enforcement of that consent belongs to the client. Do not grant full desktop control to untrusted clients.

Direct file tools restrict paths to configured local roots and refuse links,
shares and device paths. These checks are not a sandbox for arbitrary commands.
Terminal commands run as the normal Windows user, can access that user's local
files and network, and may affect other machines if explicitly instructed.
Credential-like environment variables are omitted from command children; this
does not restrict access to credentials already stored for that account.
Managed process trees terminate on timeout, pause/corner, shutdown and parent exit.
Cancellation cannot undo changes already made.

## Private data

Screenshots, file contents, command output, window titles, clipboard text, and typed content may contain confidential information. A remote MCP client can send returned content to its model provider. Read-only tools are not privacy-free.

Audit logging redacts typed and clipboard arguments by default, and always redacts developer payloads, paths, commands and stdin. Results are not audit logged; metadata can still be sensitive. Keep audit logs, screenshots, deployment records, browser profiles, credentials, and approval state out of public repositories. Never enable verbose HTTP header/body logging in production.

`web\setup-secrets.ps1` restricts relay secrets to the current owner, SYSTEM, and Administrators. It preserves existing local signing and bearer keys when rotating GitHub credentials. The private deployment file pins the machine, origin, native URL, and owner identity.

## Before publishing source

Inspect all reachable Git history, author and committer email metadata, release
assets, and CI logs as well as the current checkout. Use a GitHub noreply address
for publication commits if a personal email must stay private. A .gitignore
file does not remove anything already committed. Compare release contents against
local deployment values without printing those values. Never publish private
diagnostic traces or machine-specific configuration.

## Stop access

1. For an immediate desktop/file mutation stop and managed command cancellation, move the mouse to the top-left corner or run `scripts\pause.ps1`. Reads remain available.
2. Stop the native server and relay, or stop their startup task.
3. Disable any reverse proxy or Tailscale Funnel separately; a persistent tunnel can survive a stopped process.
4. Power off or firewall the VM for an independent boundary.

Revoke the OAuth application's authorization and rotate affected credentials after suspected exposure.

## Reporting a vulnerability

Use the repository's private security reporting feature if available. Do not open a public issue containing credentials, private URLs, screenshots, or exploit details that expose a live deployment. For urgent containment, stop the service first.
