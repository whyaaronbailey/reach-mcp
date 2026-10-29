# macOS companion plan

Status: design only. A macOS companion has not been implemented or accepted on a
real Mac. Existing Windows tests do not establish macOS support.

The companion will enroll a Mac with the existing central Reach gateway. It will
reuse the owner approval portal, phone alerts, audit records, reservations, and
administrator permission controls. The Mac will not need its own public MCP
endpoint.

## Development target and prerequisites

Start with a native Apple silicon build and a test Mac with 16 GB of memory.
Verify the installed macOS version, SDK, Xcode, Swift, and deployment target on
the actual test machine before selecting APIs or claiming compatibility. Broader
macOS and Intel support need separate build and hardware coverage.

Initial setup requires the owner to grant the applicable macOS privacy
permissions and authorize installation of the privileged helper. A distributable
installer needs a stable application identity, Developer ID signing, and
notarization. A local development build can precede distribution setup.

## Implementation order

1. **Define the device contract.** Add platform-neutral device identities, window
   identifiers, capability discovery, and desktop availability states. Keep
   Windows SID, window-handle, guest-executor, and hypervisor assumptions inside
   their Windows adapters. Identify a Mac by its enrolled device key and verified
   local identity, with explicit account and session binding.
2. **Implement enrollment and ordinary jobs.** Store credentials in Keychain.
   Authenticate the gateway connection, reconnect after network interruption,
   and retain jobs and output cursors across client polling. Implement commands,
   bounded file operations, cancellation, and process cleanup before desktop
   automation. Preserve the existing persistent enrollment and owner revocation
   model.
3. **Implement the user-session app.** Use Swift with ScreenCaptureKit for screen
   capture and the Accessibility and input APIs for desktop control. Include
   window discovery, coordinate mapping, multiple displays, keyboard shortcuts,
   Unicode, clipboard access, and application launch. Report missing or revoked
   permissions clearly. Request additional file or automation permissions only
   when the supported operation requires them.
4. **Implement approved administrator jobs.** Register a separate privileged
   helper using the supported service-management APIs. Authenticate XPC clients
   using their signing identity and verify gateway-issued, device-bound job
   authorization. The ordinary companion remains unprivileged. Support one
   operation or unlimited operations within the explicitly approved Reach
   session. Bind permission to that session and device; reject reuse after
   release, session end, or revocation. Preserve per-session and global revoke
   controls and audit every privileged job.
5. **Package recovery and updates.** Add startup integration, connection status,
   bounded recovery attempts, signed updates, and rollback. Preserve application
   identity across updates. Detect OS permission changes and explain the action
   needed. Verify laptop sleep, closed-lid, login, and restart behavior on actual
   hardware.

The privileged helper must not treat model-generated text, a tool invocation, or
the client's generic tool permission as owner approval. The existing owner
approval service remains the authority for administrator jobs. A missing client
form capability must retain the authenticated approval-page fallback.

## macOS permission and availability limits

Administrator execution does not replace macOS privacy consent. Screen capture
and Accessibility require the owner's applicable OS permissions. Stable signing
helps maintain application identity, but does not guarantee that future macOS
versions will never request consent again.

Investigate Apple's restricted Persistent Content Capture entitlement early.
Its documented scope concerns qualifying VNC applications and it requires Apple
approval. Reach's eligibility and its behavior on supported macOS versions have
not been established.

An asleep, disconnected, locked, or FileVault-protected Mac needs an explicit
availability state. Do not claim unrestricted login-screen control or universal
remote restart recovery. FileVault recovery capabilities vary with hardware,
macOS version, networking, and configuration; test the supported route without
disabling FileVault or weakening OS privacy controls.

## Acceptance matrix

Use an actual Mac and actual MCP client sessions. Record the OS, architecture,
application version, and test outcome in private test evidence, with a sanitized
public summary.

| Area | Required checks |
| --- | --- |
| Enrollment | Unique device identity, authenticated gateway connection, persistent restart behavior, owner revoke |
| Commands and files | Correct normal-user identity, read/write with hash guards, Unicode and paths, output polling, cancellation, bounded resources |
| Desktop | Capture, window discovery/focus, coordinate mapping, mouse/keyboard/clipboard, multiple displays, permission denial and revocation |
| Administrator allow | Owner approves one exact job; it runs with the expected privileged identity, returns output, and cleans up descendants |
| Administrator deny | Denial, timeout, wrong device, wrong session, tampered job, and replay cause no execution |
| Session permission | Multiple approved operations succeed; per-session revoke, global revoke, release, and session end prevent later execution |
| Recovery | Network loss, companion crash, gateway restart, sleep/wake, logout/login, Mac restart, and configured FileVault recovery |
| Updates | Signed upgrade and rollback preserve identity and fail clearly if OS permissions change |
| Client compatibility | Real command, approval-page or supported form, phone notification, polling, and release through supported clients |
| Regression | Existing Windows targets retain their identity, permissions, command, desktop, and revocation behavior |

## Local read-only preflight prompt

Replace the placeholders with the intended gateway hostname and source repository.
Do not place credentials in the prompt or commit the resulting machine inventory.

> Perform a read-only macOS Reach development preflight. Verify the OS version,
> architecture, Xcode/Swift availability, Git, and network reachability to
> `<gateway-hostname>`. Inspect the source from
> `https://github.com/<owner>/<repository>` and its applicable instructions. Report
> prerequisites and missing access. Reuse the existing gateway and owner approval
> service. Do not install software, change permissions, create credentials, or
> modify a live deployment during this preflight.

## Apple references

- [ScreenCaptureKit capture sample](https://developer.apple.com/documentation/screencapturekit/capturing-screen-content-in-macos)
- [Accessibility permission](https://support.apple.com/guide/mac-help/allow-accessibility-apps-to-access-your-mac-mh43185/mac)
- [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Developer ID signing and notarization](https://developer.apple.com/developer-id/)
- [Persistent Content Capture entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.persistent-content-capture)
- [Managing FileVault](https://support.apple.com/guide/security/sec8447f5049/web)
