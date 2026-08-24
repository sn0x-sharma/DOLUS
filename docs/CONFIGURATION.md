# DOLUS Configuration Reference

## Configuration Precedence

1. **CLI Arguments** (highest priority)
2. **Environment Variables** (`DOLUS_*`)
3. **Configuration File** (`/etc/dolus/dolus.conf`, `./dolus.conf`)
4. **Built-in Defaults** (lowest priority)

## Configuration File Format

DOLUS uses a simple INI-like format with sections and key=value pairs:

```toml
[section]
key = "value"
```

Comments start with `#`.

## Complete Configuration Options

### [server] - Network Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_addresses` | comma-separated | `0.0.0.0` | IP addresses to bind (IPv4/IPv6) |
| `ports` | comma-separated | `2222` | Ports to listen on |
| `max_connections` | integer | `1000` | Maximum concurrent connections |
| `connection_timeout_ms` | integer | `30000` | Connection timeout |
| `worker_threads` | integer | `4` | Event processing threads |

### [ssh] - SSH Protocol Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `banner_profile` | string | `ubuntu-20.04` | SSH banner profile |
| `host_key_file` | string | `/etc/dolus/host_key_rsa` | Path to host private key |
| `host_key_type` | string | `rsa` | Key type: `rsa` or `ed25519` |

#### Banner Profiles

| Profile | Banner String |
|---------|---------------|
| `ubuntu-20.04` | `OpenSSH_8.2p1 Ubuntu-4ubuntu0.3` |
| `ubuntu-22.04` | `OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` |
| `debian-11` | `OpenSSH_8.4p1 Debian-5+deb11u1` |
| `debian-12` | `OpenSSH_9.2p1 Debian-2+deb12u2` |
| `centos-7` | `OpenSSH_7.4p1, OpenSSL 1.0.2k-fips` |
| `centos-8` | `OpenSSH_8.0p1, OpenSSL 1.1.1k` |
| `alpine` | `OpenSSH_8.6_p1, OpenSSL 1.1.1l` |
| `freebsd` | `OpenSSH_8.4p1, OpenSSL 1.1.1k-freebsd` |
| `cisco` | `Cisco-1.25` |
| `dropbear` | `SSH-2.0-dropbear_2020.81` |

### [logging] - Logging Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | enum | `info` | `debug`, `info`, `warn`, `error`, `fatal` |
| `format` | enum | `text` | `text` or `json` |
| `outputs` | comma-separated | `file, stdout` | Output destinations |
| `file_path` | string | `/var/log/dolus/dolus.log` | Log file path |
| `max_size_mb` | integer | `100` | Max file size before rotation |
| `max_files` | integer | `10` | Max rotated files to keep |
| `console_output` | boolean | `false` | Also log to console |

### [storage] - Storage Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sqlite_path` | string | `/var/lib/dolus/dolus.db` | SQLite database path |
| `retention_days` | integer | `90` | Data retention period |
| `max_size_mb` | integer | `500` | Max database size |
| `enable_text_logs` | boolean | `true` | Enable text logging |
| `enable_json_logs` | boolean | `true` | Enable JSON logging |
| `enable_sqlite` | boolean | `true` | Enable SQLite storage |

### [credentials] - Credential Handling

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `policy` | enum | `redact` | `capture`, `redact`, `hash`, `metadata_only` |
| `hash_algorithm` | string | `sha256` | Hash algorithm for `hash` policy |

#### Policy Details

| Policy | Username | Password | Use Case |
|--------|----------|----------|----------|
| `capture` | ✓ Stored | ✓ Stored | Lab only |
| `redact` | ✓ Stored | ✗ `[REDACTED]` | Production default |
| `hash` | ✓ Stored | ✓ SHA-256 | Research |
| `metadata_only` | ✓ Stored | ✗ Not stored | Maximum privacy |

### [intelligence] - Analytics Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_classification` | boolean | `true` | Attack classification |
| `enable_correlation` | boolean | `true` | Campaign correlation |
| `enable_fingerprinting` | boolean | `true` | SSH fingerprinting |
| `enable_enrichment` | boolean | `false` | GeoIP/ASN enrichment |
| `geoip_db_path` | string | `/usr/share/GeoIP/GeoLite2-Country.mmdb` | MaxMind Country DB |
| `asn_db_path` | string | `/usr/share/GeoIP/GeoLite2-ASN.mmdb` | MaxMind ASN DB |

### [alerting] - Alerting Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable alerting |
| `cooldown_seconds` | integer | `60` | Alert cooldown |
| `webhook_url` | string | `` | HTTP webhook URL |
| `syslog_enabled` | boolean | `false` | Syslog alerts |
| `syslog_facility` | string | `daemon` | Syslog facility |
| `email_smtp_host` | string | `` | SMTP host |
| `email_smtp_port` | integer | `587` | SMTP port |
| `email_from` | string | `` | From address |
| `email_to` | string | `` | To address |
| `discord_webhook` | string | `` | Discord webhook |
| `slack_webhook` | string | `` | Slack webhook |

### [dashboard] - Web Dashboard

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable dashboard |
| `bind_address` | string | `127.0.0.1` | Bind address |
| `port` | integer | `8080` | Port |
| `require_auth` | boolean | `true` | Require auth token |
| `auth_token` | string | `` | Auth token (hex) |

### [metrics] - Metrics Endpoint

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable metrics |
| `bind_address` | string | `127.0.0.1` | Bind address |
| `port` | integer | `9090` | Port |

### Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `daemonize` | boolean | `false` | Run as daemon |
| `pid_file` | string | `/var/run/dolus.pid` | PID file path |

## Environment Variables

All configuration options can be set via environment variables with prefix `DOLUS_` and section/key in uppercase:

```bash
DOLUS_SERVER_BIND_ADDRESSES="0.0.0.0, ::"
DOLUS_SERVER_PORTS="2222, 2223"
DOLUS_SSH_BANNER_PROFILE="debian-12"
DOLUS_LOGGING_FORMAT="json"
DOLUS_STORAGE_SQLITE_PATH="/data/dolus.db"
DOLUS_CREDENTIALS_POLICY="hash"
DOLUS_INTELLIGENCE_ENABLE_ENRICHMENT="true"
DOLUS_ALERTING_ENABLED="true"
DOLUS_ALERTING_WEBHOOK_URL="https://example.com/webhook"
```

## CLI Overrides

```bash
dolus --config /etc/dolus/dolus.conf \
      -p 2222 \
      -b 0.0.0.0 \
      -l /var/log/dolus.log \
      -r /etc/dolus/host_key_rsa \
      -f /var/run/dolus.pid \
      -d \
      -F json \
      -v \
      start
```

## Validation

DOLUS validates configuration on startup. Invalid configuration will cause immediate exit with error message.

```bash
# Validate config
dolus --config /etc/dolus/dolus.conf config
```