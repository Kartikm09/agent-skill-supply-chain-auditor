# Constructive Code-Review Examples

These examples show the review tone expected in this repository. They are templates, not fabricated
conversations or evidence of external participation.

## Security Boundary

> **Blocking:** This helper resolves the symlink before checking whether it remains under the scan root.
> Please classify the entry with `follow_symlinks=False`, emit `FSH001`, and avoid opening the target.
> Add a test where the target contains a credential shape outside the bundle.

Why this works: it identifies the violated invariant, names the expected behaviour, and requests a
focused regression test.

## Redaction

> **Blocking:** The reporter receives the original line and performs redaction itself. That leaves room
> for a future reporter to leak the value. Please redact when constructing `Evidence`, then keep
> reporters limited to the normalized model.

Why this works: it moves the control to the earliest shared boundary instead of patching one format.

## Rule Precision

> **Suggestion:** This regular expression also matches runtime placeholders such as
> `${CALENDAR_API_TOKEN}`. Could we exclude placeholder syntax and add one positive plus one negative
> test? That should reduce noise without weakening the concrete-token case.

Why this works: it treats false-positive reduction as testable engineering work.

## Benchmark Claim

> **Blocking:** The README calls the synthetic score “real-world accuracy.” The corpus is co-authored
> with the rules, so please scope the statement to this labelled fixture set and place the limitations
> beside the metric table.

Why this works: public claims remain traceable to actual evidence.

## Maintainability

> **Suggestion:** The new formatter re-opens bundle files after scanning. Can it consume `ScanResult`
> instead? That preserves the single-read trust boundary and keeps output generation deterministic.

Why this works: it connects the refactor to an architectural property, not personal preference.

## Reviewer Checklist

- Does the change preserve static-only execution?
- Are path, byte, file-count, and depth budgets still enforced before parsing?
- Can any raw credential-shaped value enter a normalized model or report?
- Is every new rule paired with positive and nearby negative evidence?
- Are metric and security claims limited to commands actually run?
- Do all generated artifacts remain deterministic and machine-path free?
