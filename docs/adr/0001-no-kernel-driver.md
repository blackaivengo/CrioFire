# ADR 0001: No kernel driver

- Status: Accepted
- Date: 2026-11-08

## Context

A WFP callout driver could hold a new connection open while the user decides. Windows 10 and 11
load only kernel drivers signed through Microsoft's hardware portal, which needs an EV code
signing certificate and a Partner Center account. A driver bug can also crash the whole system.

## Decision

CrioFire uses only the user-mode WFP management API (`fwpuclnt.dll`). Filters are added by the
`criofire-svc` service and evaluated by Windows itself.

## Consequences

- No driver signing cost, no legal-entity hurdle for the portal, no blue-screen risk.
- Alerts work as block-then-alert: an app's first attempt is blocked, the user is asked, and
  the app succeeds on its next try once allowed.
- Filters are persistent, so protection continues if the service or app stops.
