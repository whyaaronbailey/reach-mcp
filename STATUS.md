# Reach MCP status

This is an early Windows desktop-control MCP implementation.

## Implemented

- Fifteen screenshot, mouse, keyboard, window, clipboard, wait, and application-launch tools.
- Stdio and bearer-authenticated loopback HTTP.
- A separate GitHub OAuth relay with an explicit public tool allowlist and one configured owner.
- Local approval controls with Ask as the startup default, an explicit low-risk observation policy, and temporary full-access mode.
- Input pause switches, structured audit logging, and default text-argument redaction.
- Unicode input and malformed UTF-16 handling.
- Local-only deployment identity and restricted credential storage.

## Limits and planned work

- No UI Automation tree snapshots or element actions yet. A hybrid UIA-first and screenshot-fallback design is planned.
- No AI risk classifier. Low-risk approval is a fixed policy and still permits privacy-sensitive observation.
- Approval controls on the same desktop do not provide a security boundary against an agent already able to control that desktop.
- No UAC, lock-screen, or elevated-window automation.
- Multi-monitor and mixed-DPI behavior needs broader real-hardware coverage.
- Window capture can be affected by occlusion and application-specific rendering.
- Provider account limits and billing are outside this server's control.

Machine-specific addresses, account IDs, private verification results, and deployment history belong in ignored local deployment records, not this public status file.

## Release validation

Windows VM validation includes native approval/HTTP boundary regression tests, installed-wheel checks, a real Notepad Unicode round-trip, and 16 isolated relay checks. Live ChatGPT OAuth and desktop control were verified before the Reach MCP tool rename. The installed ChatGPT app and its catalog now show all 15 renamed reach_* tools, with Always ask retained. Existing installations must refresh their client tool catalog after upgrading. Claude Chat live verification remains pending.

## Approval error reporting

Version 0.2.1 preserves actionable local-approval timeout and denial messages through the OAuth relay. Unexpected handler errors remain masked. Empty arguments are valid for reach_get_screen_info. Regression coverage includes successful handler execution and both error paths.
