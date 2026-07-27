# Roadmap

This roadmap describes possible work, not committed delivery dates.

## 0.2 - Independent Corpus

- Accept a separately maintained blinded fixture pack.
- Add mutation operators for harmless obfuscation and wording variation.
- Report confidence intervals only when the corpus design justifies them.
- Add Windows path and junction tests on a Windows CI runner.

## 0.3 - Policy Profiles

- Versioned allow/deny profiles for CI without changing base detections.
- Signed waiver records with owner, reason, scope, and expiry.
- Diff mode for two Agent-SBOMs and permission graphs.
- Rule suppression only through reviewed, repository-local configuration.

## 0.4 - Broader Formats

- Additional documented Agent Skill metadata variants.
- Optional lockfile inventory without resolving or downloading packages.
- SPDX or CycloneDX mapping after a stable agent-capability extension is defined.
- Streaming JSON output for large, bounded corpora.

## Explicitly Not Planned

- Executing an unknown bundle to “test” it
- Automatically installing dependencies
- Sending bundle content to a hosted model by default
- Scanning live credentials or exploit targets
- Treating a clean report as an execution approval
