# DOLUS Event Reference

## Overview

All DOLUS events follow a normalized JSON schema with common fields and event-type-specific data.

## Common Fields

Every event contains:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2026-08-24T10:30:00.123Z",
  "session_id": "uuid-v4",
  "event_type": "event_type_name",
  "source": {
    "ip": "192.0.2.1",
    "port": 54321,
    "family": 2
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | string | Unique event UUID |
| `timestamp` | string | ISO 8601 UTC timestamp with ms |
| `session_id` | string | Session UUID |
| `event_type` | string | Event type identifier |
| `source.ip` | string | Source IP address |
| `source.port` | integer | Source port |
| `source.family` | integer | Address family (2=IPv4, 10=IPv6) |

## Event Types

### connection_start

Emitted when a new TCP connection is accepted.

```json
{
  "event_type": "connection_start",
  "connection": {
    "client_version": "SSH-2.0-OpenSSH_8.9p1",
    "server_version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    "kex_algo": "curve25519-sha256",
    "host_key_algo": "rsa-sha2-256",
    "cipher_c2s": "aes256-gcm@openssh.com",
    "cipher_s2c": "aes256-gcm@openssh.com",
    "mac_c2s": "<implicit>",
    "mac_s2c": "<implicit>",
    "compression_c2s": "none",
    "compression_s2c": "none"
  }
}
```

### authentication_attempt

Emitted for each authentication attempt.

```json
{
  "event_type": "authentication_attempt",
  "authentication": {
    "method": "password",
    "username": "admin",
    "password_hash": "sha256:...",
    "password_redacted": true,
    "result": "failed",
    "attempt_number": 3
  }
}
```

| Method | Description |
|--------|-------------|
| `password` | Password authentication |
| `publickey` | Public key authentication |
| `keyboard_interactive` | Keyboard-interactive |
| `gssapi` | GSSAPI authentication |
| `none` | No authentication |
| `unknown` | Unknown method |

| Result | Description |
|--------|-------------|
| `success` | Authentication succeeded |
| `failed` | Authentication failed |
| `partial` | Partial success (keyboard-interactive) |

### protocol

Protocol-level events (key exchange, algorithm negotiation).

```json
{
  "event_type": "protocol",
  "connection": { ... }
}
```

### connection_end

Emitted when connection closes.

```json
{
  "event_type": "connection_end",
  "session": {
    "duration_ms": 45230,
    "auth_attempt_count": 5,
    "disconnect_reason": "client_disconnect"
  }
}
```

| Disconnect Reason | Description |
|-------------------|-------------|
| `client_disconnect` | Client closed connection |
| `key_exchange_failed` | KEX failure |
| `auth_failed` | Too many auth failures |
| `timeout` | Connection timeout |
| `server_shutdown` | Server stopping |

### classification

Behavioral classification result.

```json
{
  "event_type": "classification",
  "classification": {
    "category": "brute_force",
    "confidence": 0.85,
    "signals": [
      "high_auth_count",
      "single_username",
      "extended_duration"
    ]
  }
}
```

| Category | Description |
|----------|-------------|
| `scanner` | No auth attempts, quick disconnect |
| `brute_force` | Many attempts, few usernames |
| `credential_spray` | Many usernames, few attempts each |
| `distributed` | Correlated across multiple IPs |
| `interactive` | Successful auth, extended session |
| `unknown` | No clear pattern |

### enrichment

GeoIP/ASN/reputation enrichment data.

```json
{
  "event_type": "enrichment",
  "enrichment": {
    "country": "United States",
    "country_code": "US",
    "asn": "AS15169",
    "asn_name": "Google LLC",
    "reputation_score": 0.1,
    "is_tor": false,
    "is_proxy": false,
    "is_vpn": false
  }
}
```

### alert

Generated alert notification.

```json
{
  "event_type": "alert",
  "alert": {
    "alert_id": "uuid-v4",
    "severity": "warning",
    "category": "brute_force",
    "message": "Brute force attack detected from 192.0.2.1",
    "details": "{\"confidence\":0.85,\"attempt_count\":47}"
  }
}
```

| Severity | Description |
|----------|-------------|
| `info` | Informational |
| `warning` | Suspicious activity |
| `critical` | Confirmed attack |

## SIEM Integration

### Elasticsearch/Logstash

```json
{
  "index": "dolus-events",
  "type": "_doc"
}
```

### Splunk

```splunk
source="dolus" sourcetype="dolus:json"
```

### Graylog

GELF format supported via JSON output.

## Sigma Rule Generation

DOLUS classifications can generate Sigma rules:

```yaml
title: SSH Brute Force Attack
id: dolus-brute-force-001
status: experimental
description: Detects SSH brute force attacks identified by DOLUS
logsource:
  product: dolus
  service: ssh
detection:
  selection:
    event_type: "classification"
    classification.category: "brute_force"
    classification.confidence: "> 0.7"
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110
```