# LinkedIn Project Copy

## Featured Description

Built a static supply-chain auditor for Agent Skill bundles and MCP configurations. It detects risky instructions, secret shapes, unsafe shell guidance, unpinned dependencies, broad permissions, path hazards, and missing governance without executing scanned code.

## Project Description

I designed `agent-skill-supply-chain-auditor` as an independent security and AI-evaluation proof-of-work project. The zero-runtime-dependency Python scanner performs bounded filesystem inspection, skips symlinks, redacts credential-shaped evidence, and generates deterministic JSON, Markdown, SARIF, Agent-SBOM, and permission-graph outputs. A labelled synthetic fixture corpus measures rule behavior, while the dashboard lets reviewers inspect findings, permissions, files, remediation, and redacted evidence.

## Resume Bullet

- Built a static Python supply-chain auditor for Agent Skills and MCP configs with 17 review rules, bounded hostile-input handling, five deterministic report formats, 10 labelled synthetic fixtures, 59 tests, CI/CodeQL, and an interactive evidence dashboard.

## Application Answer

This project demonstrates how I review agent artifacts before execution. The scanner separates untrusted bytes from normalized findings, enforces file/count/depth limits, refuses symlink traversal, strips machine paths, redacts likely secrets, and documents every rule's confidence and false-positive boundary. The benchmark is intentionally synthetic and is presented as regression evidence, not a security certification.

## Skills

Python · AI Security · Static Analysis · MCP · Agent Skills · Supply-Chain Risk · SARIF · SBOM · QA · CI/CD
