# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub: **Security -> Report a vulnerability** on this repository
(private vulnerability reporting). Include the CrioFire version, Windows version and
architecture, and steps to reproduce.

We aim to acknowledge reports within 3 business days and to agree on a disclosure date with you.

## Scope

In scope: ways to bypass or disable CrioFire rules without administrator rights, privilege
escalation through `criofire-svc` or its local API, tampering with signed releases, and
anything that could leave a PC unexpectedly cut off from the network.

## What a firewall cannot do

CrioFire controls which programs may use the network. Malware already running with
administrator rights can remove any user-mode filter, and code injected into an allowed program
inherits that program's access. CrioFire alerts on changes where it can, but it is not antivirus.
