# Shared gateway and owner approvals reference

This directory contains a sanitized reference of the shared Reach gateway,
outbound Windows worker protocol, browser approval portal, Web Push delivery,
and host owner broker. It supplements the native Windows package in `../src`.
It is source for development and review; it is not an installer or a ready
production deployment. A macOS worker has not been implemented or tested here.

The example origin is `https://reach.example.invalid`. VM names, account
identifiers, UUIDs, network addresses, and host paths are synthetic. They do not
enroll a machine or grant permission. No deployment configuration, owner grants,
credentials, certificates, push subscriptions, logs, or live state are included.

## Components

- `gateway.py`, `channel.py`, and `registry.py`: authenticated MCP routing,
  enrollment, persistent desktop authorization, isolated workflow claims,
  transport bindings, and claim release.
- `admin_frontend.py`: administrator request preparation, supported client
  approval transports, owner-page fallback, polling, and broker communication.
- `approval_portal.py`: separate owner browser login, approve/deny decisions,
  session grants, per-session/global revocation, Home Screen assets,
  notification subscriptions, encryption, and Web Push delivery.
- `deployment_policy.py` and `owner_network_model.py`: strict policy,
  attestation, boundary, and network evidence validation.
- `native_worker.py` and `boundary_probe.py`: the outbound Windows worker and
  diagnostic interface. The worker uses the public `reach_mcp` package and
  retains Windows account/session identity requirements.
- `host/core` and `host/broker`: protected host permission ledger, workflow
  fencing, dispatch, receipt validation, and broker protocol reference.

`legacy_channel.py` and `legacy_private_api.py` are kept for regression tests;
the Dockerfile does not install them. `restart_acceptance.py` retains strict
image/container checks with deliberately unset example pins. It cannot certify
any deployment until a reviewed installation supplies its own identities.

## Local application tests

Use a separate Python 3.12 environment and install `requirements.lock`, then:

```text
python gateway/run_tests.py
python -m unittest discover -s gateway/host/tests -p "test_*.py"
```

The application runner injects a synthetic test fence into test registry
instances because the production registry requires a protected host lock. The
runner changes no production source or installed service and never supplies a
production owner grant. Some tests create temporary loopback TLS servers;
they do not contact an enrolled machine or real OAuth service.

PHP host fixtures are described in [host/README.md](host/README.md). Passing unit
tests establishes fixture behavior, not desktop, phone, deployment, or macOS
acceptance.

## Configuration and deployment boundary

An installation must independently configure and review its origin and exact
callback/host checks, OAuth clients and owner identity, TLS trust, device
enrollment, policy evidence, protected broker paths, peer credentials, and
source manifests. The sample allowlists deliberately admit only three synthetic
Windows targets. Adding a platform requires a reviewed device/identity adapter;
changing a label does not add macOS support.

The source preserves approval checks, exact operation hashes, current-claim
verification, revocation, and integrity gates. An unconfigured deployment must
remain unavailable rather than substituting approvals or bypassing checks.

For a Mac port, reuse the gateway and owner approval lifecycle while replacing
Windows SID/session, desktop APIs, process cleanup, and privileged execution
with supported macOS implementations. The root helper must verify the current
Nexus-hosted owner decision and session binding before every elevated dispatch.
The public examples do not contain a route to any existing private host.
