# Reach MCP status

This is an early Windows desktop-control MCP implementation.

## Implemented

- Fifteen screenshot, mouse, keyboard, window, clipboard, wait, and application-launch tools.
- Stdio and bearer-authenticated loopback HTTP.
- A separate GitHub OAuth relay with an explicit public tool allowlist and one configured owner.
- Explicit startup approval policies: `local` (the default) starts in Ask mode with a fixed low-risk observation mode and temporary full-access mode; `client` delegates consent to the connected client's permission controls without a local approval queue.
- Input pause switches, structured audit logging, and default text-argument redaction.
- Unicode input and malformed UTF-16 handling.
- Local-only deployment identity and restricted credential storage.

## Limits and planned work

- No UI Automation tree snapshots or element actions yet. A hybrid UIA-first and screenshot-fallback design is planned.
- No AI risk classifier. Low-risk approval is a fixed policy and still permits privacy-sensitive observation.
- Local approval controls on the same desktop do not provide a security boundary against an agent already able to control that desktop.
- Client-managed approval relies on the connected client to enforce consent. The native MCP server does not receive cryptographic proof of a human's chat approval.
- No UAC, lock-screen, or elevated-window automation.
- Multi-monitor and mixed-DPI behavior needs broader real-hardware coverage.
- Window capture can be affected by occlusion and application-specific rendering.
- Provider account limits and billing are outside this server's control.

Machine-specific addresses, account IDs, private verification results, and deployment history belong in ignored local deployment records, not this public status file.

## Release validation

Windows VM validation includes native approval/HTTP boundary regression tests, installed-wheel checks, a real Notepad Unicode round-trip, and 16 isolated relay checks. Live ChatGPT OAuth and desktop control were verified before the Reach MCP tool rename. The installed ChatGPT app and its catalog now show all 15 renamed reach_* tools, with Always ask retained. Existing installations must refresh their client tool catalog after upgrading. Claude Chat live verification remains pending.

## Approval error reporting

Version 0.2.1 preserves actionable local-approval timeout and denial messages through the OAuth relay. Unexpected handler errors remain masked. Empty arguments are valid for reach_get_screen_info. Regression coverage includes successful handler execution and both error paths.

## Client-managed approvals

Version 0.2.2 adds `--approval-policy client` to the native server and `-ApprovalPolicy client` to the web runner. Select the chat client's permission controls, such as ChatGPT's Always ask, to approve requests only from the chat. No decision in the VM is required under this policy. Startup tasks must retain the explicit parameter to use it after restarts.

The omitted-parameter default remains `local`, which starts in Ask mode and retains the local approval panel's three modes. Client policy does not expire into local Ask mode. Both policies keep authentication, loopback listeners, disabled-tool rules, input kill switches, and audit logging.

Client-policy validation includes 144 native tests, owner-authorization checks, native-to-relay regression tests, and a live OAuth connection returning screen information without a VM approval request. The local policy retains its separate approval and safety regression coverage.
