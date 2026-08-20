# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you find a security issue in SmartFuzz, please **do not** open a public GitHub issue for exploit details.

Email or DM the maintainer with:

- Description of the issue
- Steps to reproduce
- Impact assessment

We aim to acknowledge reports within 72 hours.

## Scope

SmartFuzz is an **authorized security testing** tool. Misuse against systems you do not own or lack permission to test is out of scope for vulnerability reports in this repository.

## Safe defaults

- Rate limiting and adaptive throttling are enabled by default
- Wordlist downloads use public SecLists URLs only
- No telemetry or external scanning APIs are used
