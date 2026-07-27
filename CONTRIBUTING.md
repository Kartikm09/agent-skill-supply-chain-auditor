# Contributing

Thank you for improving this independent defensive project. Contributions must preserve the static-only
trust boundary and use synthetic, portfolio-safe examples.

## Local Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt -e .
make verify
```

Do not execute files under `fixtures/vulnerable/`. They are inert test inputs, and all tests must inspect
them through `scan_path` or the CLI.

## Change Workflow

1. Open an issue describing the reviewer problem and expected evidence.
2. Create a focused branch.
3. Add tests before or with implementation.
4. Run `make verify` and include the exact result in the pull request.
5. Explain any rule severity, confidence, or compatibility decision.

Use Conventional Commit style where practical: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, or
`chore:`.

## Rule Contributions

Every new or broadened rule needs:

- a stable ID and documented category;
- severity, confidence, message, remediation, and tags;
- at least one positive synthetic fixture;
- at least one negative test near the match boundary;
- expected labels in `fixtures/labels.json`;
- regenerated reports when sample output changes; and
- explicit false-positive and false-negative notes in the rule catalogue.

Do not submit real secrets, copied private prompts, client code, exploit targets, malware, or commands
that tests execute.

## Pull-Request Checklist

- [ ] Scanned third-party content is never imported, executed, or resolved.
- [ ] Symlinks and paths cannot escape the selected root.
- [ ] Evidence is redacted before it reaches reporters.
- [ ] Output contains no absolute machine paths or wall-clock values.
- [ ] Tests cover success, malformed input, and the relevant negative boundary.
- [ ] `make verify` passes.
- [ ] Documentation and generated evidence match actual behaviour.
- [ ] No confidential, copyrighted, or identity-bearing material was added without permission.

## Maintainer Response Guide

Maintainers should acknowledge reproducible defects, separate policy debate from implementation review,
and explain blocking feedback through an invariant or test. Security reports follow `SECURITY.md` and
should not be discussed publicly before a fix is available.
