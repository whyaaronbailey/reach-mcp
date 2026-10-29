# Host owner broker reference

`core/` and `broker/` preserve the protected permission ledger, exact request
hashes, current-claim fencing, process collection, owner choices, revocation and
receipt validation from the gateway implementation. All target identities and
host paths in this export are synthetic examples.

Two deployment pins are intentionally unset: the broker's core-manifest hash
and the third target's guest-executor hash are 64 zeroes. No live manifests or
executors are shipped. A real installation must build manifests from its
reviewed source, configure protected paths and identity-specific guest
executors, pin those artifacts, and independently pass deployment acceptance.
The zero placeholders retain hash checks and cause an unconfigured route to
refuse; they are not wildcard pins.

`nexus_transport.php` demonstrates two local executor routes and one restricted
SSH route. It requires separately installed guest executors, keys and host-key
pins that are not part of this repository. Its example network addresses do
not identify an existing host. These adapters target Windows guests; they are
not the future macOS privileged helper.

## Isolated fixtures

Python ledger and live-claim fixtures run without a real broker or guest:

```text
python -m unittest discover -s gateway/host/tests -p "test_*.py"
```

The PHP fixtures require Linux PHP with `posix` and process support. Syntax can
be checked without running a fixture. The broker and adapter fixtures use
harmless local fixture children:

```text
php gateway/host/tests/test_broker.php
php gateway/host/tests/test_vm2_adapter.php
```

`test_dispatch.php`, `test_reduction.php`, and `test_fence.php` exercise Linux
root ownership, process and UID boundaries. Run them only in a disposable Linux
test environment with no production mounts, credentials, network or services.
Read each fixture's required arguments and UID before running it. No fixture
result is evidence of a real owner approval or completed administrator command.
