# ADR 0003: Source-available license, paid for business use

Status: accepted · November 2026 · Supersedes the license part of ADR 0002

## Context

CrioSoft LLC wants CrioFire to be free for private, personal use and paid for enterprise and
commercial use. GPL-3.0, the original license, cannot express that: it forbids further restrictions
such as "no commercial use" and lets recipients remove them, and selling a commercial license next to
GPL does not make businesses pay, because GPL already allows internal use for free.

CrioSoft owns all of CrioFire's code: it was written for this project, with no code taken from other
projects and no outside contributions, and nothing has been released. So it can change the license.

## Decision

- **Public license:** PolyForm Noncommercial License 1.0.0, a standard, plainly written license. It
  allows personal use and use by charities, educational institutions, public research, public safety
  or health, environmental organizations and government institutions, and allows changing and
  sharing the code for those purposes.
- **CrioSoft Additional Permissions** in the LICENSE file: any use, including commercial, on up to 3
  computers per organization (with affiliates); a one-time 30-day business evaluation on up to 10
  computers. Not included: reselling, bundling into products, or managing clients' computers as a
  paid service.
- **Commercial license:** a yearly subscription per protected computer, with volume tiers, updates
  and email support (COMMERCIAL-LICENSE.md, a draft for counsel to review).
- **Contributions:** a Contributor License Agreement (CLA.md) so CrioSoft can offer contributed code
  under both licenses.

## Consequences

- CrioFire is described as source-available, not open source.
- Versions already published under GPL-3.0 stay GPL-3.0 for those who received them; the change
  applies from the commit that adds this ADR.
- Code from GPL-licensed projects can no longer be copied into CrioFire.
- Licensing is on the honor system for now. A license key in the app, if wanted later, is a
  separate decision.
- Third-party tools and libraries must allow commercial use; check the WiX Toolset's maintenance-fee
  terms before shipping a paid product built with it.
