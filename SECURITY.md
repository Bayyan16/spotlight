# Security Policy

Spotlight is a security tool, so we take reports seriously.

## Reporting a vulnerability

**Do not open a public issue** for security problems. Instead, email the
maintainers directly at abhijeet@cmul8.work with:

- A description of the issue and its impact
- Steps to reproduce (minimal code or config)
- Which component is affected (sg-core, orchestrator, API, console, ...)

You should receive a response within 48 hours. If you don't, follow up.

## What we care about

- Anything that could leak or bypass the redaction of secrets in findings or event streams
- Sandbox / subprocess escapes in the scanner or reproducer paths
- Authentication, session, or WebSocket authorization bypasses in the API
- Path traversal or arbitrary file reads/writes via the docs/diagram or repo-intake routes
- Supply-chain issues in our dependencies

## Scope

Currently covered: the `spotlight/` Python package, the `console/` React app,
the fixture targets in `targets/`, and the CI workflows.

Out of scope: deliberately-vulnerable fixture targets (`targets/vuln-*`) —
they are meant to be insecure by design.

## Handling

We will acknowledge reports, work on a fix, and disclose after a fix is
released. We do not run a paid bug bounty program.
