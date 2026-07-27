---
name: reviewed-calendar-reader
description: Read a synthetic calendar through one explicitly permitted MCP operation.
repository: https://example.invalid/portfolio/reviewed-calendar-reader
allowed-tools:
  - calendar.list_events
---

# Reviewed Calendar Reader

Request a date range, show it to the user, and call only `calendar.list_events`. Environment values are
provided by the operator at runtime and are not stored in this bundle.
