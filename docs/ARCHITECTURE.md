# DOLUS Architecture Document

## Current Architecture (v0.0.4)

### Overview
The current DOLUS implementation is a single-file SSH honeypot (`src/ssh-honeypot.c`, 266 lines) that:
- Listens on a single IPv4 port using libssh
- Forks a child process per connection
- Logs password authentication attempts to a text file
- Supports daemon mode and PID file management
- Uses hardcoded configuration with CLI overrides

### Components

#### 1. SSH Engine (`ssh-honeypot.c`)
- `main()`: Entry point, argument parsing, daemonization, listener setup
- `handle_ssh_auth()`: Key exchange, authentication message handling, logging
- `get_ssh_ip()`: Extracts client IPv4 address from session
- `log_entry()`: Timestamped text logging to file and optionally stdout
- `write_pid_file()`: PID file management

#### 2. Configuration (`config.h`)
Hardcoded `#define` constants:
- VERSION, AUTHOR
- LOGFILE, PIDFILE, PORT, RSAKEY, BINDADDR, BANNER

#### 3. Build System (`Makefile`)
Simple gcc build with `-static-libgcc` and `-lssh`

#### 4. Analysis Scripts (`scripts/`)
8 shell scripts for log parsing:
- Unique passwords (with/without counts)
- Unique IPs (scanners, password attempts)
- Geolocation lookup
- Top 10 usernames/passwords
- PID check/respawn script

### Limitations Identified

| Category | Issues |
|----------|--------|
| **Architecture** | Monolithic single file, global mutable state, no separation of concerns |
| **Networking** | IPv4 only, single listener, no connection limits |
| **Session Tracking** | No session IDs, no lifecycle events, no connection duration |
| **Logging** | Text-only, no structured format, opens/closes file per entry |
| **Storage** | No database, no retention, no indexing |
| **Security** | Plaintext passwords in logs, no credential policies |
| **Reliability** | Fork per connection (no pooling), no graceful shutdown, no signal handling |
| **Observability** | No metrics, no health checks, no dashboard |
| **Extensibility** | No plugin system, no alerting, no SIEM integration |
| **Testing** | No tests, no static analysis, no sanitizers |
| **Deployment** | No systemd, no Docker, no config file |

---

## Proposed Architecture (v1.0+)

### High-Level Structure

```
DOLUS
├── Core
│   ├── lifecycle         # Init/shutdown, signal handling
│   ├── configuration     # Config file, CLI, env vars, validation
│   ├── logging           # Structured logging (text/JSON), rotation
│   └── error_handling    # Error types, result patterns
│
├── SSH Engine
│   ├── listener          # Multi-listener, IPv4/IPv6, connection limits
│   ├── sessions          # Session lifecycle, unique IDs, tracking
│   ├── authentication    # Auth methods, attempt tracking, policies
│   └── banners           # Configurable banner profiles
│
├── Event Engine
│   ├── event_model       # Normalized event types, schema
│   ├── session_tracker   # Session reconstruction
│   ├── event_pipeline    # Async processing, backpressure
│   └── normalization     # Field standardization
│
├── Storage
│   ├── text_logs         # Backward-compatible text logging
│   ├── json_logs         # Structured JSON output
│   ├── sqlite_backend    # Normalized schema, prepared statements
│   └── retention         # Size/time-based cleanup
│
├── Intelligence
│   ├── statistics        # Aggregations, trends
│   ├── scanner_detection # Behavioral classification
│   ├── attack_classification # Brute force, spray, distributed
│   ├── campaign_correlation # Multi-source correlation
│   ├── fingerprinting    # SSH client fingerprinting
│   ├── attacker_profiles # Source behavior profiles
│   └── enrichment        # GeoIP, ASN, reputation (opt-in)
│
├── Alerting
│   ├── webhook           # HTTP webhooks
│   ├── syslog            # RFC 5424
│   ├── email             # SMTP
│   └── integrations      # Discord, Slack, etc.
│
├── Management
│   ├── cli               # Subcommand-based CLI
│   ├── health            # Health checks, readiness
│   └── metrics           # Prometheus-compatible /stats
│
└── Deployment
      ├── systemd         # Service file, hardening
      ├── docker          # Dockerfile, compose, healthcheck
      └── config          # Example configs
```

### Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  SSH Client │────▶│ SSH Listener │────▶│   Session   │
└─────────────┘     └─────────────┘     │  Manager    │
                                         └──────┬──────┘
                                                │
                    ┌─────────────┐     ┌───────▼───────┐
                    │  Storage    │◀────│ Event Pipeline │
                    │ (Text/JSON/ │     │ (Normalized)  │
                    │  SQLite)    │     └───────┬───────┘
                    └──────┬──────┘             │
                           │                    │
              ┌────────────▼────────────┐  ┌────▼────┐
              │   Intelligence Engine   │  │Alerting │
              │ (Classification, Stats, │  └────┬────┘
              │  Correlation, Profiles) │       │
              └────────────┬────────────┘       │
                           │                    │
                    ┌──────▼──────┐      ┌──────▼──────┐
                    │   CLI/API   │      │  Dashboard  │
                    └─────────────┘      └─────────────┘
```

### Event Model

All events share a common base:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2026-08-24T10:30:00.123Z",
  "session_id": "uuid-v4",
  "event_type": "connection_start|authentication_attempt|connection_end|classification|alert",
  "source": {
    "ip": "192.0.2.1",
    "port": 54321,
    "family": "IPv4"
  },
  "metadata": { ... }
}
```

#### Event Types

1. **connection_start** - New TCP connection accepted
2. **protocol_event** - Key exchange, version exchange, etc.
3. **authentication_attempt** - Auth method, username, result
4. **session_event** - Channel open, subsystem request, etc.
5. **connection_end** - Disconnect, duration, reason
6. **classification** - Behavioral classification result
7. **enrichment** - GeoIP, ASN, reputation data
8. **alert** - Triggered alert with severity

### Session Model

```
Session
├── session_id (UUID)
├── connection_start (timestamp)
├── connection_end (timestamp, optional)
├── duration_ms (computed)
├── source_ip, source_port
├── destination_ip, destination_port
├── ssh_version_client
├── ssh_version_server (banner)
├── kex_algorithms
├── host_key_algorithm
├── authentication_attempts[]
│   ├── attempt_id
│   ├── timestamp
│   ├── method (password/publickey/keyboard-interactive)
│   ├── username
│   ├── result (success/failed/partial)
│   └── credential_policy_applied
├── classification
│   ├── category (scanner/brute_force/credential_spray/distributed/interactive/unknown)
│   ├── confidence (0.0-1.0)
│   ├── signals[]
└── enrichment
    ├── country
    ├── asn
    ├── reputation_score
```

### Database Schema (SQLite)

```sql
-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    start_time INTEGER NOT NULL,  -- Unix epoch ms
    end_time INTEGER,             -- Unix epoch ms
    duration_ms INTEGER,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    client_version TEXT,
    server_version TEXT,
    kex_algo TEXT,
    host_key_algo TEXT,
    classification_category TEXT,
    classification_confidence REAL,
    signals TEXT,  -- JSON array
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

CREATE INDEX idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX idx_sessions_start_time ON sessions(start_time);
CREATE INDEX idx_sessions_classification ON sessions(classification_category);

-- Authentication events
CREATE TABLE auth_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    timestamp INTEGER NOT NULL,
    method TEXT NOT NULL,
    username TEXT,
    password_hash TEXT,  -- Only if policy=hash
    password_redacted INTEGER DEFAULT 1,
    result TEXT NOT NULL,  -- success/failed/partial
    attempt_number INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

CREATE INDEX idx_auth_session ON auth_events(session_id);
CREATE INDEX idx_auth_timestamp ON auth_events(timestamp);
CREATE INDEX idx_auth_username ON auth_events(username);

-- Source profiles (materialized view / cache)
CREATE TABLE source_profiles (
    src_ip TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    session_count INTEGER DEFAULT 0,
    auth_attempt_count INTEGER DEFAULT 0,
    unique_usernames INTEGER DEFAULT 0,
    classifications TEXT,  -- JSON: {"brute_force": 5, "scanner": 2}
    country TEXT,
    asn TEXT,
    reputation_score REAL,
    updated_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

CREATE INDEX idx_source_last_seen ON source_profiles(last_seen);

-- Enrichment cache
CREATE TABLE enrichment_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    asn TEXT,
    reputation_score REAL,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Alerts
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    severity TEXT NOT NULL,  -- info/warning/critical
    category TEXT NOT NULL,
    source_ip TEXT,
    session_id TEXT,
    message TEXT NOT NULL,
    details TEXT,  -- JSON
    acknowledged INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_severity ON alerts(severity);
```

### Configuration System

Priority order (highest wins):
1. CLI arguments
2. Environment variables (`DOLUS_*`)
3. Configuration file (`/etc/dolus/dolus.conf` or `./dolus.conf`)
4. Built-in defaults

Configuration file format (TOML):

```toml
[server]
bind_addresses = ["0.0.0.0", "::"]
ports = [2222]
max_connections = 1000
connection_timeout_ms = 30000

[ssh]
banner_profile = "ubuntu-20.04"
host_key_file = "/etc/dolus/host_key_rsa"
host_key_type = "rsa"

[logging]
level = "info"
format = "json"  # text, json
outputs = ["file", "stdout"]
file_path = "/var/log/dolus/dolus.log"
max_size_mb = 100
max_files = 10

[storage]
sqlite_path = "/var/lib/dolus/dolus.db"
retention_days = 90
max_size_mb = 500

[credentials]
policy = "redact"  # capture, redact, hash, metadata_only
hash_algorithm = "sha256"

[intelligence]
enable_classification = true
enable_correlation = true
enable_fingerprinting = true
enable_enrichment = false
geoip_db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

[alerting]
enabled = false
cooldown_seconds = 60
webhook_url = ""
syslog_enabled = false

[dashboard]
enabled = false
bind_address = "127.0.0.1"
port = 8080
require_auth = true

[metrics]
enabled = true
bind_address = "127.0.0.1"
port = 9090
```

### Migration Strategy

#### Phase 1: Foundation (Weeks 1-2)
1. Create modular directory structure
2. Implement core infrastructure (config, logging, error handling)
3. Extract SSH engine into separate module
4. Implement event model and session tracking
5. Add JSON logging (alongside text for compatibility)

#### Phase 2: Storage & Intelligence (Weeks 3-4)
1. Add SQLite backend with schema
2. Implement retention policies
3. Build classification engine (scanner, brute_force, spray)
4. Add attacker profiling
5. Implement campaign correlation

#### Phase 3: Operations (Weeks 5-6)
1. Redesign CLI with subcommands
2. Add alerting subsystem
3. Implement systemd service
4. Create Dockerfile and compose
5. Add health checks and metrics

#### Phase 4: Advanced Features (Weeks 7-8)
1. SSH fingerprinting
2. Adaptive personas
3. Optional fake shell emulator
4. Session replay
5. Local dashboard (optional)

#### Phase 5: Hardening & Quality (Weeks 9-10)
1. Security audit (sanitizers, static analysis)
2. Performance benchmarks
3. Test suite (unit + integration)
4. Documentation overhaul
5. Backward compatibility verification

### Backward Compatibility

| Feature | Strategy |
|---------|----------|
| CLI flags (-p, -b, -l, -r, -f, -d) | Preserved as global options |
| Text log format | Preserved as default, JSON opt-in |
| PID file | Preserved |
| Daemon mode | Preserved |
| RSA key file | Preserved |
| Banner selection | Extended to profiles |
| Analysis scripts | Kept as compatibility layer, new CLI commands preferred |

### Security Considerations

1. **Credential Handling**: Default to `redact` policy; never log passwords by default
2. **Network Input**: All SSH input treated as untrusted; bounds checking everywhere
3. **Privileges**: Drop privileges after binding; non-root execution
4. **External Calls**: Enrichment opt-in only; no data exfiltration by default
5. **Database**: Prepared statements only; no SQL injection possible
6. **Logging**: No sensitive data in structured logs/metrics/alerts
7. **Dashboard**: Localhost-only by default; auth required for remote

### Performance Targets

- Handle 10,000+ concurrent connections
- <1ms event processing latency (p99)
- <50MB RSS at 1000 concurrent sessions
- SQLite write throughput >10k events/sec
- Graceful degradation under load (backpressure, connection limits)

---

## Implementation Checklist

### Core Infrastructure
- [ ] Configuration system (TOML parser, validation, priority merging)
- [ ] Structured logging (text/JSON, rotation, multiple outputs)
- [ ] Error handling framework (result types, error codes)
- [ ] Signal handling (SIGTERM, SIGINT, SIGHUP, SIGUSR1)
- [ ] Lifecycle management (init, run, shutdown)

### SSH Engine
- [ ] Multi-listener support (IPv4 + IPv6)
- [ ] Connection pooling / worker threads (replace fork)
- [ ] Session ID generation (UUID v4)
- [ ] Session lifecycle tracking
- [ ] Configurable banner profiles
- [ ] Host key management (RSA, Ed25519)
- [ ] Authentication method tracking
- [ ] Graceful shutdown with connection draining

### Event Engine
- [ ] Event model definition (C structs + JSON serialization)
- [ ] Session tracker (in-memory + persistence)
- [ ] Event pipeline (ring buffer, worker threads)
- [ ] Normalization layer

### Storage
- [ ] Text logger (backward compatible)
- [ ] JSON logger (structured)
- [ ] SQLite backend (schema, migrations, prepared statements)
- [ ] Retention manager (size/time based)

### Intelligence
- [ ] Statistics aggregator
- [ ] Scanner detection (heuristic)
- [ ] Brute force detection
- [ ] Credential spray detection
- [ ] Distributed attack correlation
- [ ] SSH client fingerprinting
- [ ] Attacker profile builder
- [ ] GeoIP/ASN enrichment (opt-in, cached)

### Alerting
- [ ] Alert engine (dedup, cooldown, severity)
- [ ] Webhook handler
- [ ] Syslog handler
- [ ] Email handler
- [ ] Discord/Slack webhook

### Management
- [ ] Subcommand CLI (start, stop, status, config, stats, sessions, attackers, scanners, events, db, version)
- [ ] Health endpoint
- [ ] Metrics endpoint (Prometheus format)

### Deployment
- [ ] systemd service file
- [ ] Dockerfile (multi-stage, non-root, minimal)
- [ ] docker-compose.yml
- [ ] Example configuration files

### Quality
- [ ] Unit tests (config, events, storage, classification)
- [ ] Integration tests (SSH listener, full pipeline)
- [ ] Fuzzing (malformed SSH packets)
- [ ] Sanitizer builds (ASan, UBSan)
- [ ] Static analysis (clang-tidy, cppcheck)
- [ ] Benchmarks

### Documentation
- [ ] README.md (complete rewrite)
- [ ] docs/ARCHITECTURE.md (this file)
- [ ] docs/CONFIGURATION.md
- [ ] docs/EVENTS.md
- [ ] docs/DATABASE.md
- [ ] docs/ANALYTICS.md
- [ ] docs/DEPLOYMENT.md
- [ ] docs/DETECTION.md
- [ ] docs/DEVELOPMENT.md
- [ ] docs/SECURITY.md