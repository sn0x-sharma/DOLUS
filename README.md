# DOLUS

### Deception-Driven SSH Honeypot & Attack Intelligence

<p align="center">

  <b>Observe. Deceive. Collect. Analyze.</b>

  <br><br>

  Lightweight SSH honeypot designed to attract, record,
  and analyze unauthorized SSH authentication activity.

</p>

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
