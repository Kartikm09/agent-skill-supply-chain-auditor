# Tooling security repair — 18 September 2026

The application runtime remains unchanged. A fresh dependency audit identified vulnerable pinned
development/build tools: setuptools75.8.2 (PYSEC-2025-49, PYSEC-2026-3447) and pytest8.3.5
(PYSEC-2026-1845). The isolated Python bootstrap also supplied pip25.0.1 with archive/wheel/install
path advisories. These findings affect development/build inputs, not proof of an exploited service.

Targeted pins are setuptools83.0.0, pytest9.0.3 and pip26.2.1; lint versions and runtime functionality
are retained. The full verification command, source build and separate runtime/build dependency
audits must pass before publication. No blanket upgrade or vulnerability suppression is used.

The existing main-branch Pages deployment workflow is preserved. Publishing a feature PR does not
trigger it; merging rebuilds the existing public dashboard. The deployment configuration is unchanged.
