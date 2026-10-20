# Reach MCP status

This is a Windows desktop and developer-tool MCP implementation.

## Implemented

- Thirty tools: fifteen desktop tools plus capabilities, direct files/search/patches, and managed terminal jobs.
- Stdio and bearer-authenticated loopback HTTP.
- A separate GitHub OAuth relay with an explicit public tool allowlist and one configured owner.
- Explicit startup approval policies: `local` (the default) starts in Ask mode with a fixed low-risk observation mode and temporary full-access mode; `client` delegates consent to the connected client's permission controls without a local approval queue.
- Desktop/file mutation pause switches, managed process-tree safety stops, structured audit event IDs, and payload redaction.
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

## Desktop availability and client guidance

Version 0.2.3 reports the selected approval policy and interactive Windows session
availability in screen information. Locked, disconnected, or inaccessible desktops
are rejected before input dispatch, and known Windows desktop access failures return
an actionable, sanitized error through the relay. Interrupted input may be partial,
so clients are instructed to inspect the target before retrying.

Native instructions now describe the actual startup policy. Relay instructions
explicitly separate Windows session availability from local approval failures.
Unknown handler errors remain masked. No Windows unlock, credential entry, automatic
login, locking-policy change, elevation, or secure-desktop bypass is implemented.

Validation includes 157 native tests and four native-to-relay error tests, including
locked-session rejection and an interruption during typing. Full live text entry
still requires an unlocked interactive desktop; unit tests use synthetic sessions.

## Direct developer tools (0.3.0)

Direct local text files, bounded directory/text/name search, SHA256-guarded writes,
exact replacements and standard unified patches are implemented alongside desktop control.
Existing-file edits preserve BOM/newline style; multi-file patches preflight all hunks
and attempt rollback on I/O failure. File roots reject shares, device paths and links.
Moves do not overwrite; deletion is non-recursive.

Managed PowerShell/cmd/program jobs expose stdout, stderr, exit code, cursor-based
output polling, stdin, cancellation and job listing. Jobs start suspended inside a
Windows kill-on-close Job Object. Timeouts, pause/corner, shutdown and normal parent
exit remove descendants. Output, runtime, job count and stdin are bounded.

Terminal commands have the Windows user's file/network permissions; file roots
are not a shell sandbox. File and terminal operations do not need an unlocked desktop.
No Codex, OpenCode or other AI client is called to perform ordinary Reach tools.

Developer payloads, commands, stdin and paths are always audit-redacted. Tool results
are not written to the audit log. Expected developer errors return safe messages;
unexpected details stay masked. See [usage audit](docs/usage.md) for official usage
distinctions, a non-model quota collector and a quiet-window test. An account-level
zero-usage experiment has not been completed during active Codex development.

Validation for 0.3.0 includes 237 native tests, seven owner/configuration checks,
four native-to-relay error checks, and 20 isolated relay checks. Managed process
tests also pass under a non-administrator desktop token. A real Notepad Unicode
round-trip and saved-file check pass. Wheel and source distributions are built;
installed-wheel discovery is checked separately. Refresh the client catalog to
discover the additional tools. Live Claude Chat verification remains pending.
