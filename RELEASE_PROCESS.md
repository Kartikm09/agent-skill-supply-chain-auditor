# Release Process

1. Confirm the intended version follows Semantic Versioning.
2. Run `make verify` from a clean checkout on Python 3.11 or newer.
3. Confirm `git diff --exit-code -- reports dashboard/data/sample-scan.json` is clean.
4. Review the generated reports for raw credentials, absolute paths, and unsupported claims.
5. Update `CHANGELOG.md` and the version in `pyproject.toml` plus `version.py` together.
6. Build and smoke-test the container.
7. Create a signed or annotated tag only after CI passes.
8. Publish release notes that distinguish implemented facts from roadmap items.

No release should claim independent corpus accuracy, runtime sandboxing, production adoption, or hosted
deployment without corresponding public evidence.
