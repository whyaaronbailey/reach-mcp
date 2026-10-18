# Security model

This project exposes the privileges of a Windows desktop user. A model that can send keyboard and mouse input can open a terminal, modify files, access signed-in applications, and send data. Tool approvals reduce accidental or unintended use; they do not contain a malicious client.

## Boundaries

- Use a dedicated VM and a non-administrator account.
- The native server and approval panel listen on loopback. The native HTTP endpoint requires its own bearer token.
- The optional public relay requires GitHub OAuth and exactly one immutable numeric owner ID. OAuth authenticates the owner; it does not prove approval for each action or identify an individual chat.
- The relay exposes only the listed desktop tools. The approval panel is never proxied.
- Ask mode is the startup default. Temporary automatic modes expire. The low-risk mode uses a documented observation allowlist, not a semantic risk classifier.
- Approval decisions apply to the pending call and arguments. They are not a general grant to a conversation.

The control panel is on the same desktop the agent controls. A client with sufficient input access may be able to interact with it, read local state, or alter this application's files. Loopback tokens and file ACLs do not isolate processes running as the same Windows user. Keep approvals in a separate trusted client or management device when a stronger human-only boundary is required. Do not grant full desktop control to untrusted clients.

## Private data

Screenshots, window titles, clipboard text, and typed content may contain confidential information. A remote MCP client can send returned content to its model provider. Read-only tools are not privacy-free.

Audit logging redacts typed and clipboard arguments by default, but tool metadata and other arguments may still be sensitive. Keep audit logs, screenshots, deployment records, browser profiles, credentials, and approval state out of public repositories. Never enable verbose HTTP header/body logging in production.

`web\setup-secrets.ps1` restricts relay secrets to the current owner, SYSTEM, and Administrators. It preserves existing local signing and bearer keys when rotating GitHub credentials. The private deployment file pins the machine, origin, native URL, and owner identity.

## Before publishing source

Inspect all reachable Git history, author and committer email metadata, release
assets, and CI logs as well as the current checkout. Use a GitHub noreply address
for publication commits if a personal email must stay private. A .gitignore
file does not remove anything already committed. Compare release contents against
local deployment values without printing those values. Never publish private
diagnostic traces or machine-specific configuration.

## Stop access

1. For an immediate input stop, move the mouse to the top-left corner or run `scripts\pause.ps1`. Reads remain available.
2. Stop the native server and relay, or stop their startup task.
3. Disable any reverse proxy or Tailscale Funnel separately; a persistent tunnel can survive a stopped process.
4. Power off or firewall the VM for an independent boundary.

Revoke the OAuth application's authorization and rotate affected credentials after suspected exposure.

## Reporting a vulnerability

Use the repository's private security reporting feature if available. Do not open a public issue containing credentials, private URLs, screenshots, or exploit details that expose a live deployment. For urgent containment, stop the service first.
