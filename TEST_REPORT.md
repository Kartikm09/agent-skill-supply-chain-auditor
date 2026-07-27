# Test Report

Date: 2026-07-27  
Environment: macOS, Python 3.12.13

## Verified Results

| Gate | Result |
|---|---|
| Ruff lint and format | Passed; 24 files formatted |
| Python compilation | Passed |
| Pytest | 59 passed in 0.30 seconds |
| Synthetic labelled corpus | 10 fixtures, 14 positive rule labels |
| Rule-level classification | 14 TP, 0 FP, 0 FN |
| Report determinism | 5/5 output formats byte-stable |
| Repository validator | 13 JSON/SARIF and 29 Markdown files validated |
| Secret scan | 89 text files checked; no credential-shaped leak found |
| Wheel smoke test | Built, installed, and scanned the safe fixture with zero findings |
| Dashboard | Four findings loaded; high filter returned three; redacted detail verified |
| Docker | Not run locally; Docker CLI is not installed. CI contains a container build gate. |

## Commands

```bash
make verify PYTHON=.venv/bin/python
.venv/bin/python -m pip wheel . --no-deps --wheel-dir .cache/final-wheel
```

## Interpretation

The perfect synthetic-corpus metrics apply only to fixtures co-developed with the rules. They do not estimate performance on unknown repositories, prove malicious intent, or certify runtime safety.
