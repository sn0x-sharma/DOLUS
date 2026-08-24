<img width="1983" height="793" alt="ChatGPT Image Aug 24, 2026, 08_44_23 AM" src="https://github.com/user-attachments/assets/9c07b43b-3610-44f2-ac92-6d1938c6a00f" />

### Lightweight SSH honeypot designed to attract, record, and analyze unauthorized SSH authentication activity.
---

## Overview

**DOLUS** is a lightweight SSH honeypot and attack-intelligence
toolkit designed to observe SSH brute-force activity, scanners,
credential-guessing behavior, and authentication patterns.

Instead of exposing a real SSH service, DOLUS provides a controlled
SSH endpoint that records incoming authentication attempts for
security research and defensive analysis.

The project is useful for:

- SSH attack monitoring
- Brute-force intelligence
- Scanner identification
- Credential-guessing analysis
- Honeypot research
- Threat-intelligence collection
- Security monitoring
- Defensive research
- Red/Blue-team exercises
- Internet-facing deception environments

---

## Why DOLUS?

SSH remains one of the most frequently targeted services exposed
to the Internet.

A normal SSH server generally records failed authentication attempts,
but a honeypot can provide a dedicated environment for studying
attacker behavior without exposing legitimate services.

DOLUS is designed around a simple concept:

```text
                    INTERNET
                        │
                        ▼
                 ┌─────────────┐
                 │    DOLUS    │
                 │ SSH Honeypot│
                 └──────┬──────┘
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
            IPs     Usernames   Passwords
              │         │         │
              └─────────┼─────────┘
                        ▼
                  Attack Analysis
