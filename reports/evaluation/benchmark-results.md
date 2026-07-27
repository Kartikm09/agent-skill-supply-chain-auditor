# Synthetic Fixture Evaluation

> This benchmark uses only labelled synthetic bundles. It is not a claim about detection performance on unknown real-world repositories.

## Metrics

| Fixture count | TP | FP | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 14 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

The scoring unit is one unique rule ID per fixture.

## Fixture Results

| Fixture | Expected | Predicted | Unexpected | Missed |
|---|---|---|---|---|
| safe-mcp | None | None | None | None |
| safe-minimal | None | None | None | None |
| vulnerable-broad-mcp | `MCP001`, `MCP002`, `PATH001`, `SEC001` | `MCP001`, `MCP002`, `PATH001`, `SEC001` | None | None |
| vulnerable-dangerous-installer | `CMD001`, `DEP001` | `CMD001`, `DEP001` | None | None |
| vulnerable-malformed-mcp | `MCP003` | `MCP003` | None | None |
| vulnerable-missing-governance | `LIC001`, `PROV001` | `LIC001`, `PROV001` | None | None |
| vulnerable-prompt-injection | `INJ001` | `INJ001` | None | None |
| vulnerable-secret-exposure | `SEC001` | `SEC001` | None | None |
| vulnerable-unpinned-dependencies | `DEP001` | `DEP001` | None | None |
| vulnerable-unsafe-network-path | `NET001`, `PATH001` | `NET001`, `PATH001` | None | None |

## Limitations

- Metrics describe this small synthetic corpus only and do not estimate field performance.
- Rule-level scoring does not measure duplicate finding quality or runtime behaviour.
- The corpus was authored with the rules and should be supplemented by independent datasets.
