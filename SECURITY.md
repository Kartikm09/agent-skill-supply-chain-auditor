# Security Policy

## Supported Version

The latest `0.1.x` revision is supported while this portfolio project is pre-1.0. Older commits may not
receive fixes.

## Reporting a Vulnerability

Use GitHub's private vulnerability-reporting feature for this repository after publication. Include:

- affected version or commit;
- minimal synthetic reproduction;
- violated security invariant;
- impact and expected behaviour; and
- whether public discussion already exists.

Do not include real credentials, private Agent Skills, client data, malware, or a live exploit target.
Please allow a reasonable period for validation and remediation before public disclosure.

## Security Guarantees

The scanner is designed not to import or execute bundle content, follow symlinks, retain absolute target
paths, or emit recognized credential values in evidence. CI tests these properties on supported runners.

## Important Non-Guarantees

This project is not a sandbox, antivirus engine, package vulnerability database, or runtime policy
enforcer. A clean report does not prove safety. Pattern rules can miss obfuscation and can flag quoted or
educational content. Use isolation, source review, immutable dependencies, and least privilege before
running unknown software.

## Repository Security Checks

`make verify` runs linting, tests, bytecode compilation, deterministic report generation, the labelled
fixture evaluation, and a credential-shape scan outside explicitly vulnerable synthetic fixtures.
CodeQL runs in GitHub Actions. No telemetry or automatic SARIF upload occurs in the local CLI.
