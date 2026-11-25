# Security policy

This library is a prototype, not a production system. There is no release line to support: only the latest commit on the default branch is maintained.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub private reporting instead:

1. Open the [Security tab](https://github.com/ahmedbadawy4/pii-redaction-toolkit/security).
2. Choose **Report a vulnerability**.
3. Describe the problem and how to reproduce it.

Reports are read on a best-effort basis. If a report is valid, the fix goes to the default branch first and the advisory is published after that.

## What counts

- A way to make `redact` return text that still holds a value it says it finds, or to make a fail-closed detector fail without `DetectorFailure`.
- A pattern that takes quadratic or worse time on crafted input.

A value the detectors do not recognise is a known limit, listed in the README under Limitations. Report that as a normal issue with a made-up example, never with real personal data or real secrets.
