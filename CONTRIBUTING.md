# Contributing

Use Windows and Python 3.12. Start with `scripts\setup.ps1`, then run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Native desktop smoke tests need an interactive, non-elevated desktop and explicit approval. Do not run them unattended on a machine with valuable open documents or sensitive clipboard contents.

The relay has a separate environment:

```powershell
.\web\setup.ps1
.\web\.venv\Scripts\python.exe web\test_owner.py -q
```

Relay integration tests are documented in [web/README.md](web/README.md). Never publish a development tunnel merely to run tests.

Keep changes focused. Add meaningful regression coverage when changing permission enforcement, authentication, transport validation, Unicode input, coordinates, or audit redaction. Do not weaken safety defaults to make a test pass.

For a new desktop tool, update its permission classification, tests, documentation, and audit behavior. Public relay exposure is an explicit separate decision; do not automatically publish new native tools.

Before proposing a change:

- Run applicable unit tests and syntax checks.
- Keep private deployment details and generated files out of the patch.
- Describe behavior changes, verification, and known limitations.
- Preserve dependency license notices and record provenance for imported code.

Contributions are provided under the repository's MIT license.
