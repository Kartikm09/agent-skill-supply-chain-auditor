# Methodology

## Evaluation Question

For each labelled synthetic bundle, does the scanner emit the expected set of unique rule IDs and avoid
unexpected rule IDs?

This is a regression benchmark for the implemented rules, not an estimate of real-world security
accuracy.

## Corpus

The manifest contains 10 synthetic directories:

- two clean controls;
- prompt override and concealment instructions;
- a remote shell bootstrap command;
- a credential-shaped value;
- an overprivileged shell-backed MCP declaration;
- missing provenance and license;
- malformed MCP JSON;
- unpinned Python and npm packages; and
- an insecure remote endpoint with path traversal.

No fixture references a real organization, credential, package target, customer, or private system.
Vulnerable fixture commands and JSON are inert test strings and are never run.

## Label Unit

The evaluation unit is `(fixture ID, unique rule ID)`. If one fixture contains two lines that trigger the
same rule, that counts as one predicted label. This keeps the metric focused on rule coverage and means
it does **not** score duplicate-finding quality.

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

An unexpected rule for a fixture is a false positive. A missing expected rule is a false negative. Empty
safe fixtures contribute false positives if any rule appears, but they do not create artificial true
negatives because true-negative counts are not meaningful without defining every possible rule/fixture
pair.

## Reproduction

```bash
make benchmark
```

The command writes deterministic JSON and Markdown to `reports/evaluation/` and exits non-zero when a
false positive or false negative exists.

Current verified corpus result:

| Fixtures | Label unit | TP | FP | FN | Precision | Recall | F1 |
|---:|---|---:|---:|---:|---:|---:|---:|
| 10 | Unique rule per fixture | 14 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

## Limitations

1. The same project authored both rules and fixtures, creating construction bias.
2. The corpus is small and does not represent the distribution of public Agent Skills.
3. It does not include independent adversarial mutation, multilingual instruction attacks, or encoded
   payloads.
4. Rule-level scoring ignores finding localization quality beyond the tests.
5. Precision and recall on this corpus must not be generalized to unknown data.

## Responsible Interpretation

Use the benchmark to detect regressions while changing rules. Use independent corpora, blinded labels,
and representative prevalence before making broader performance claims. A production adoption decision
should combine static findings with source review, dependency verification, sandboxed runtime testing,
and least-privilege policy.
