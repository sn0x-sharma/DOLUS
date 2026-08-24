#include "config.h"
#include "dolus.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#define MAX_LINE 4096

static void trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

static char *strdup_safe(const char *str) {
    if (!str) return NULL;
    char *dup = strdup(str);
    return dup;
}

static char **parse_comma_list(const char *str, size_t *count) {
    if (!str) {
        *count = 0;
        return NULL;
    }
    
    char *copy = strdup(str);
    char *token = strtok(copy, ",");
    size_t capacity = 4;
    char **result = calloc(capacity, sizeof(char *));
    *count = 0;
    
    while (token) {
        trim_whitespace(token);
        if (*count >= capacity) {
            capacity *= 2;
            result = realloc(result, capacity * sizeof(char *));
        }
        result[(*count)++] = strdup_safe(token);
        token = strtok(NULL, ",");
    }
    
    free(copy);
    return result;
}

dolus_error_t dolus_config_parse_int(const char *str, int *out) {
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (endptr == str || *endptr != '\0') return DOLUS_ERROR_INVALID;
    *out = (int)val;
    return DOLUS_OK;
}

dolus_error_t dolus_config_parse_size_t(const char *str, size_t *out) {
    char *endptr;
    unsigned long val = strtoul(str, &endptr, 10);
    if (endptr == str || *endptr != '\0') return DOLUS_ERROR_INVALID;
    *out = (size_t)val;
    return DOLUS_OK;
}

void dolus_config_free_string_array(char **arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; i++) {
        free(arr[i]);
    }
    free(arr);
}

static dolus_error_t parse_int(const char *str, int *out) {
    return dolus_config_parse_int(str, out);
}

static dolus_error_t parse_size_t(const char *str, size_t *out) {
    return dolus_config_parse_size_t(str, out);
}

static void free_string_array(char **arr, size_t count) {
    dolus_config_free_string_array(arr, count);
}

static void config_set_defaults(dolus_config_t *config) {
    config->server.bind_addresses = calloc(1, sizeof(char *));
    config->server.bind_addresses[0] = strdup("0.0.0.0");
    config->server.bind_address_count = 1;
    config->server.ports = calloc(1, sizeof(int));
    config->server.ports[0] = 2222;
    config->server.port_count = 1;
    config->server.max_connections = 1000;
    config->server.connection_timeout_ms = 30000;
    config->server.worker_threads = 4;

    config->ssh.banner_profile = strdup("ubuntu-20.04");
    config->ssh.host_key_file = strdup("/etc/dolus/host_key_rsa");
    config->ssh.host_key_type = strdup("rsa");
    config->ssh.banner_count = 0;
    config->ssh.banners = NULL;

    config->logging.level = DOLUS_LOG_INFO;
    config->logging.format = DOLUS_LOG_FORMAT_TEXT;
    config->logging.outputs = calloc(2, sizeof(char *));
    config->logging.outputs[0] = strdup("file");
    config->logging.outputs[1] = strdup("stdout");
    config->logging.output_count = 2;
    config->logging.file_path = strdup("/var/log/dolus/dolus.log");
    config->logging.max_size_mb = 100;
    config->logging.max_files = 10;
    config->logging.console_output = true;

    config->storage.sqlite_path = strdup("/var/lib/dolus/dolus.db");
    config->storage.retention_days = 90;
    config->storage.max_size_mb = 500;
    config->storage.enable_text_logs = true;
    config->storage.enable_json_logs = true;
    config->storage.enable_sqlite = true;

    config->credentials.policy = DOLUS_CRED_REDACT;
    config->credentials.hash_algorithm = strdup("sha256");

    config->intelligence.enable_classification = true;
    config->intelligence.enable_correlation = true;
    config->intelligence.enable_fingerprinting = true;
    config->intelligence.enable_enrichment = false;
    config->intelligence.geoip_db_path = strdup("/usr/share/GeoIP/GeoLite2-Country.mmdb");
    config->intelligence.asn_db_path = strdup("/usr/share/GeoIP/GeoLite2-ASN.mmdb");

    config->alerting.enabled = false;
    config->alerting.cooldown_seconds = 60;
    config->alerting.webhook_url = NULL;
    config->alerting.syslog_enabled = false;
    config->alerting.syslog_facility = strdup("daemon");
    config->alerting.email_smtp_host = NULL;
    config->alerting.email_smtp_port = 587;
    config->alerting.email_from = NULL;
    config->alerting.email_to = NULL;
    config->alerting.discord_webhook = NULL;
    config->alerting.slack_webhook = NULL;

    config->dashboard.enabled = false;
    config->dashboard.bind_address = strdup("127.0.0.1");
    config->dashboard.port = 8080;
    config->dashboard.require_auth = true;
    config->dashboard.auth_token = NULL;

    config->metrics.enabled = true;
    config->metrics.bind_address = strdup("127.0.0.1");
    config->metrics.port = 9090;

    config->daemonize = false;
    config->pid_file = strdup("/var/run/dolus.pid");
    config->config_file = NULL;
}

dolus_config_t *dolus_config_new(void) {
    dolus_config_t *config = calloc(1, sizeof(dolus_config_t));
    if (!config) return NULL;
    config_set_defaults(config);
    return config;
}

void dolus_config_free(dolus_config_t *config) {
    if (!config) return;
    
    free_string_array(config->server.bind_addresses, config->server.bind_address_count);
    free(config->server.ports);
    
    free(config->ssh.banner_profile);
    free(config->ssh.host_key_file);
    free(config->ssh.host_key_type);
    free_string_array(config->ssh.banners, config->ssh.banner_count);
    
    free_string_array(config->logging.outputs, config->logging.output_count);
    free(config->logging.file_path);
    
    free(config->storage.sqlite_path);
    
    free(config->credentials.hash_algorithm);
    
    free(config->intelligence.geoip_db_path);
    free(config->intelligence.asn_db_path);
    
    free(config->alerting.syslog_facility);
    free(config->alerting.webhook_url);
    free(config->alerting.email_smtp_host);
    free(config->alerting.email_from);
    free(config->alerting.email_to);
    free(config->alerting.discord_webhook);
    free(config->alerting.slack_webhook);
    
    free(config->dashboard.bind_address);
    free(config->dashboard.auth_token);
    
    free(config->metrics.bind_address);
    
    free(config->pid_file);
    free(config->config_file);
    
    free(config);
}

static dolus_error_t parse_config_line(dolus_config_t *config, const char *line) {
    char key[MAX_LINE] = {0};
    char value[MAX_LINE] = {0};
    
    const char *eq = strchr(line, '=');
    if (!eq) return DOLUS_OK;
    
    size_t key_len = eq - line;
    if (key_len >= MAX_LINE) return DOLUS_ERROR_INVALID;
    strncpy(key, line, key_len);
    trim_whitespace(key);
    
    const char *val_start = eq + 1;
    while (isspace((unsigned char)*val_start)) val_start++;
    strncpy(value, val_start, MAX_LINE - 1);
    trim_whitespace(value);
    
    if (value[0] == '"' && value[strlen(value) - 1] == '"') {
        value[strlen(value) - 1] = '\0';
        memmove(value, value + 1, strlen(value) + 1);
    }
    
    #define SET_STR(field) do { free(config->field); config->field = strdup_safe(value); } while(0)
    #define SET_INT(field) do { parse_int(value, &config->field); } while(0)
    #define SET_SIZE(field) do { parse_size_t(value, &config->field); } while(0)
    #define SET_BOOL(field) do { config->field = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0); } while(0)
    #define SET_ENUM(field, enum_map) do { \
        for (int i = 0; enum_map[i].name; i++) { \
            if (strcmp(value, enum_map[i].name) == 0) { \
                config->field = enum_map[i].value; \
                break; \
            } \
        } \
    } while(0)
    
    if (strcmp(key, "server.bind_addresses") == 0) {
        free_string_array(config->server.bind_addresses, config->server.bind_address_count);
        config->server.bind_addresses = parse_comma_list(value, &config->server.bind_address_count);
    } else if (strcmp(key, "server.ports") == 0) {
        free(config->server.ports);
        char **parts = parse_comma_list(value, &config->server.port_count);
        config->server.ports = calloc(config->server.port_count, sizeof(int));
        for (size_t i = 0; i < config->server.port_count; i++) {
            parse_int(parts[i], &config->server.ports[i]);
        }
        free_string_array(parts, config->server.port_count);
    } else if (strcmp(key, "server.max_connections") == 0) SET_INT(server.max_connections);
    else if (strcmp(key, "server.connection_timeout_ms") == 0) SET_INT(server.connection_timeout_ms);
    else if (strcmp(key, "server.worker_threads") == 0) SET_INT(server.worker_threads);
    
    else if (strcmp(key, "ssh.banner_profile") == 0) SET_STR(ssh.banner_profile);
    else if (strcmp(key, "ssh.host_key_file") == 0) SET_STR(ssh.host_key_file);
    else if (strcmp(key, "ssh.host_key_type") == 0) SET_STR(ssh.host_key_type);
    
    else if (strcmp(key, "logging.level") == 0) {
        static const struct { const char *name; dolus_log_level_t value; } levels[] = {
            {"debug", DOLUS_LOG_DEBUG}, {"info", DOLUS_LOG_INFO}, {"warn", DOLUS_LOG_WARN},
            {"error", DOLUS_LOG_ERROR}, {"fatal", DOLUS_LOG_FATAL}, {NULL, 0}
        };
        SET_ENUM(logging.level, levels);
    } else if (strcmp(key, "logging.format") == 0) {
        static const struct { const char *name; dolus_log_format_t value; } formats[] = {
            {"text", DOLUS_LOG_FORMAT_TEXT}, {"json", DOLUS_LOG_FORMAT_JSON}, {NULL, 0}
        };
        SET_ENUM(logging.format, formats);
    } else if (strcmp(key, "logging.outputs") == 0) {
        free_string_array(config->logging.outputs, config->logging.output_count);
        config->logging.outputs = parse_comma_list(value, &config->logging.output_count);
    } else if (strcmp(key, "logging.file_path") == 0) SET_STR(logging.file_path);
    else if (strcmp(key, "logging.max_size_mb") == 0) SET_SIZE(logging.max_size_mb);
    else if (strcmp(key, "logging.max_files") == 0) SET_INT(logging.max_files);
    else if (strcmp(key, "logging.console_output") == 0) SET_BOOL(logging.console_output);
    
    else if (strcmp(key, "storage.sqlite_path") == 0) SET_STR(storage.sqlite_path);
    else if (strcmp(key, "storage.retention_days") == 0) SET_INT(storage.retention_days);
    else if (strcmp(key, "storage.max_size_mb") == 0) SET_SIZE(storage.max_size_mb);
    else if (strcmp(key, "storage.enable_text_logs") == 0) SET_BOOL(storage.enable_text_logs);
    else if (strcmp(key, "storage.enable_json_logs") == 0) SET_BOOL(storage.enable_json_logs);
    else if (strcmp(key, "storage.enable_sqlite") == 0) SET_BOOL(storage.enable_sqlite);
    
    else if (strcmp(key, "credentials.policy") == 0) {
        static const struct { const char *name; dolus_cred_policy_t value; } policies[] = {
            {"capture", DOLUS_CRED_CAPTURE}, {"redact", DOLUS_CRED_REDACT},
            {"hash", DOLUS_CRED_HASH}, {"metadata_only", DOLUS_CRED_METADATA_ONLY}, {NULL, 0}
        };
        SET_ENUM(credentials.policy, policies);
    } else if (strcmp(key, "credentials.hash_algorithm") == 0) SET_STR(credentials.hash_algorithm);
    
    else if (strcmp(key, "intelligence.enable_classification") == 0) SET_BOOL(intelligence.enable_classification);
    else if (strcmp(key, "intelligence.enable_correlation") == 0) SET_BOOL(intelligence.enable_correlation);
    else if (strcmp(key, "intelligence.enable_fingerprinting") == 0) SET_BOOL(intelligence.enable_fingerprinting);
    else if (strcmp(key, "intelligence.enable_enrichment") == 0) SET_BOOL(intelligence.enable_enrichment);
    else if (strcmp(key, "intelligence.geoip_db_path") == 0) SET_STR(intelligence.geoip_db_path);
    else if (strcmp(key, "intelligence.asn_db_path") == 0) SET_STR(intelligence.asn_db_path);
    
    else if (strcmp(key, "alerting.enabled") == 0) SET_BOOL(alerting.enabled);
    else if (strcmp(key, "alerting.cooldown_seconds") == 0) SET_INT(alerting.cooldown_seconds);
    else if (strcmp(key, "alerting.webhook_url") == 0) SET_STR(alerting.webhook_url);
    else if (strcmp(key, "alerting.syslog_enabled") == 0) SET_BOOL(alerting.syslog_enabled);
    else if (strcmp(key, "alerting.syslog_facility") == 0) SET_STR(alerting.syslog_facility);
    else if (strcmp(key, "alerting.email_smtp_host") == 0) SET_STR(alerting.email_smtp_host);
    else if (strcmp(key, "alerting.email_smtp_port") == 0) SET_INT(alerting.email_smtp_port);
    else if (strcmp(key, "alerting.email_from") == 0) SET_STR(alerting.email_from);
    else if (strcmp(key, "alerting.email_to") == 0) SET_STR(alerting.email_to);
    else if (strcmp(key, "alerting.discord_webhook") == 0) SET_STR(alerting.discord_webhook);
    else if (strcmp(key, "alerting.slack_webhook") == 0) SET_STR(alerting.slack_webhook);
    
    else if (strcmp(key, "dashboard.enabled") == 0) SET_BOOL(dashboard.enabled);
    else if (strcmp(key, "dashboard.bind_address") == 0) SET_STR(dashboard.bind_address);
    else if (strcmp(key, "dashboard.port") == 0) SET_INT(dashboard.port);
    else if (strcmp(key, "dashboard.require_auth") == 0) SET_BOOL(dashboard.require_auth);
    else if (strcmp(key, "dashboard.auth_token") == 0) SET_STR(dashboard.auth_token);
    
    else if (strcmp(key, "metrics.enabled") == 0) SET_BOOL(metrics.enabled);
    else if (strcmp(key, "metrics.bind_address") == 0) SET_STR(metrics.bind_address);
    else if (strcmp(key, "metrics.port") == 0) SET_INT(metrics.port);
    
    else if (strcmp(key, "daemonize") == 0) SET_BOOL(daemonize);
    else if (strcmp(key, "pid_file") == 0) SET_STR(pid_file);
    
    return DOLUS_OK;
}

dolus_error_t dolus_config_load(dolus_config_t *config, const char *path) {
    if (!config || !path) return DOLUS_ERROR_INVALID;
    
    FILE *fp = fopen(path, "r");
    if (!fp) return DOLUS_ERROR_NOTFOUND;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        dolus_error_t err = parse_config_line(config, line);
        if (err != DOLUS_OK) {
            fclose(fp);
            return err;
        }
    }
    
    fclose(fp);
    config->config_file = strdup_safe(path);
    return DOLUS_OK;
}

dolus_error_t dolus_config_load_defaults(dolus_config_t *config) {
    if (!config) return DOLUS_ERROR_INVALID;
    config_set_defaults(config);
    return DOLUS_OK;
}

dolus_error_t dolus_config_apply_env(dolus_config_t *config) {
    if (!config) return DOLUS_ERROR_INVALID;
    
    #define ENV_STR(prefix, key, field) do { \
        char env_key[256]; \
        snprintf(env_key, sizeof(env_key), "%s_%s", prefix, key); \
        const char *val = getenv(env_key); \
        if (val) { free(config->field); config->field = strdup_safe(val); } \
    } while(0)
    
    #define ENV_INT(prefix, key, field) do { \
        char env_key[256]; \
        snprintf(env_key, sizeof(env_key), "%s_%s", prefix, key); \
        const char *val = getenv(env_key); \
        if (val) parse_int(val, &config->field); \
    } while(0)
    
    #define ENV_BOOL(prefix, key, field) do { \
        char env_key[256]; \
        snprintf(env_key, sizeof(env_key), "%s_%s", prefix, key); \
        const char *val = getenv(env_key); \
        if (val) config->field = (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "1") == 0); \
    } while(0)
    
    {
        const char *val = getenv("DOLUS_BIND_ADDRESSES");
        if (val) {
            free_string_array(config->server.bind_addresses, config->server.bind_address_count);
            config->server.bind_addresses = parse_comma_list(val, &config->server.bind_address_count);
        }
    }
    {
        const char *val = getenv("DOLUS_PORT");
        if (val) parse_int(val, &config->server.ports[0]);
    }
    ENV_INT("DOLUS", "MAX_CONNECTIONS", server.max_connections);
    ENV_INT("DOLUS", "CONNECTION_TIMEOUT_MS", server.connection_timeout_ms);
    
    ENV_STR("DOLUS", "BANNER_PROFILE", ssh.banner_profile);
    ENV_STR("DOLUS", "HOST_KEY_FILE", ssh.host_key_file);
    
    ENV_INT("DOLUS", "LOG_LEVEL", logging.level);
    {
        const char *val = getenv("DOLUS_LOG_FORMAT");
        if (val) {
            if (strcmp(val, "json") == 0) config->logging.format = DOLUS_LOG_FORMAT_JSON;
            else config->logging.format = DOLUS_LOG_FORMAT_TEXT;
        }
    }
    ENV_STR("DOLUS", "LOG_FILE", logging.file_path);
    
    ENV_STR("DOLUS", "SQLITE_PATH", storage.sqlite_path);
    ENV_INT("DOLUS", "RETENTION_DAYS", storage.retention_days);
    
    {
        const char *val = getenv("DOLUS_CRED_POLICY");
        if (val) {
            if (strcmp(val, "capture") == 0) config->credentials.policy = DOLUS_CRED_CAPTURE;
            else if (strcmp(val, "hash") == 0) config->credentials.policy = DOLUS_CRED_HASH;
            else if (strcmp(val, "metadata_only") == 0) config->credentials.policy = DOLUS_CRED_METADATA_ONLY;
            else config->credentials.policy = DOLUS_CRED_REDACT;
        }
    }
    
    ENV_BOOL("DOLUS", "ENABLE_CLASSIFICATION", intelligence.enable_classification);
    ENV_BOOL("DOLUS", "ENABLE_ENRICHMENT", intelligence.enable_enrichment);
    
    ENV_BOOL("DOLUS", "ALERTING_ENABLED", alerting.enabled);
    ENV_STR("DOLUS", "WEBHOOK_URL", alerting.webhook_url);
    
    ENV_BOOL("DOLUS", "DAEMONIZE", daemonize);
    ENV_STR("DOLUS", "PID_FILE", pid_file);
    
    return DOLUS_OK;
}

dolus_error_t dolus_config_apply_cli(dolus_config_t *config, int argc, char **argv) {
    if (!config) return DOLUS_ERROR_INVALID;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (++i < argc) parse_int(argv[i], &config->server.ports[0]);
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0) {
            if (++i < argc) {
                free_string_array(config->server.bind_addresses, config->server.bind_address_count);
                config->server.bind_addresses = calloc(1, sizeof(char *));
                config->server.bind_addresses[0] = strdup(argv[i]);
                config->server.bind_address_count = 1;
            }
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log-file") == 0) {
            if (++i < argc) SET_STR(logging.file_path);
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--host-key") == 0) {
            if (++i < argc) SET_STR(ssh.host_key_file);
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--pid-file") == 0) {
            if (++i < argc) SET_STR(pid_file);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0) {
            config->daemonize = true;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (++i < argc) {
                config->config_file = strdup(argv[i]);
            }
        } else if (strcmp(argv[i], "--log-format") == 0) {
            if (++i < argc) {
                if (strcmp(argv[i], "json") == 0) config->logging.format = DOLUS_LOG_FORMAT_JSON;
            }
        }
    }
    
    return DOLUS_OK;
}

dolus_error_t dolus_config_validate(const dolus_config_t *config) {
    if (!config) return DOLUS_ERROR_INVALID;
    
    if (config->server.bind_address_count == 0) return DOLUS_ERROR_CONFIG;
    if (config->server.port_count == 0) return DOLUS_ERROR_CONFIG;
    if (config->server.max_connections <= 0) return DOLUS_ERROR_CONFIG;
    if (config->server.connection_timeout_ms <= 0) return DOLUS_ERROR_CONFIG;
    if (config->server.worker_threads <= 0) return DOLUS_ERROR_CONFIG;
    
    if (!config->ssh.host_key_file || strlen(config->ssh.host_key_file) == 0) return DOLUS_ERROR_CONFIG;
    
    if (!config->logging.file_path) return DOLUS_ERROR_CONFIG;
    
    if (config->storage.enable_sqlite && (!config->storage.sqlite_path || strlen(config->storage.sqlite_path) == 0)) {
        return DOLUS_ERROR_CONFIG;
    }
    
    return DOLUS_OK;
}

void dolus_config_print(const dolus_config_t *config) {
    if (!config) return;
    printf("DOLUS Configuration:\n");
    printf("  Server:\n");
    printf("    Bind addresses: ");
    for (size_t i = 0; i < config->server.bind_address_count; i++) {
        printf("%s%s", i > 0 ? ", " : "", config->server.bind_addresses[i]);
    }
    printf("\n    Ports: ");
    for (size_t i = 0; i < config->server.port_count; i++) {
        printf("%d%s", config->server.ports[i], i > 0 ? ", " : "");
    }
    printf("\n    Max connections: %d\n", config->server.max_connections);
    printf("  SSH:\n");
    printf("    Banner profile: %s\n", config->ssh.banner_profile);
    printf("    Host key: %s\n", config->ssh.host_key_file);
    printf("  Logging:\n");
    printf("    Level: %d\n", config->logging.level);
    printf("    Format: %s\n", config->logging.format == DOLUS_LOG_FORMAT_JSON ? "json" : "text");
    printf("    File: %s\n", config->logging.file_path);
    printf("  Storage:\n");
    printf("    SQLite: %s\n", config->storage.sqlite_path);
    printf("  Credentials:\n");
    printf("    Policy: %d\n", config->credentials.policy);
}