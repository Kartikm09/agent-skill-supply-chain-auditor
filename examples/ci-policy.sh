#!/bin/sh
set -eu

# Exit 1 when the local bundle contains a high or critical finding.
skill-auditor scan ./my-skill --output-dir ./audit-output --format sarif --fail-on high
