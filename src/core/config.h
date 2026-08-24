#ifndef DOLUS_CONFIG_H
#define DOLUS_CONFIG_H

#include "dolus.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_server_config {
    char **bind_addresses;
    size_t bind_address_count;
    int *ports;
    size_t port_count;
    int max_connections;
    int connection_timeout_ms;
    int worker_threads;
} dolus_server_config_t;

typedef struct dolus_ssh_config {
    char *banner_profile;
    char *host_key_file;
    char *host_key_type;
    int banner_count;
    char **banners;
} dolus_ssh_config_t;

typedef struct dolus_logging_config {
    dolus_log_level_t level;
    dolus_log_format_t format;
    char **outputs;
    size_t output_count;
    char *file_path;
    size_t max_size_mb;
    int max_files;
    bool console_output;
} dolus_logging_config_t;

typedef struct dolus_storage_config {
    char *sqlite_path;
    int retention_days;
    size_t max_size_mb;
    bool enable_text_logs;
    bool enable_json_logs;
    bool enable_sqlite;
} dolus_storage_config_t;

typedef enum {
    DOLUS_CRED_CAPTURE = 0,
    DOLUS_CRED_REDACT = 1,
    DOLUS_CRED_HASH = 2,
    DOLUS_CRED_METADATA_ONLY = 3
} dolus_cred_policy_t;

typedef struct dolus_credentials_config {
    dolus_cred_policy_t policy;
    char *hash_algorithm;
} dolus_credentials_config_t;

typedef struct dolus_intelligence_config {
    bool enable_classification;
    bool enable_correlation;
    bool enable_fingerprinting;
    bool enable_enrichment;
    char *geoip_db_path;
    char *asn_db_path;
} dolus_intelligence_config_t;

typedef struct dolus_alerting_config {
    bool enabled;
    int cooldown_seconds;
    char *webhook_url;
    bool syslog_enabled;
    char *syslog_facility;
    char *email_smtp_host;
    int email_smtp_port;
    char *email_from;
    char *email_to;
    char *discord_webhook;
    char *slack_webhook;
} dolus_alerting_config_t;

typedef struct dolus_dashboard_config {
    bool enabled;
    char *bind_address;
    int port;
    bool require_auth;
    char *auth_token;
} dolus_dashboard_config_t;

typedef struct dolus_metrics_config {
    bool enabled;
    char *bind_address;
    int port;
} dolus_metrics_config_t;

typedef struct dolus_config {
    dolus_server_config_t server;
    dolus_ssh_config_t ssh;
    dolus_logging_config_t logging;
    dolus_storage_config_t storage;
    dolus_credentials_config_t credentials;
    dolus_intelligence_config_t intelligence;
    dolus_alerting_config_t alerting;
    dolus_dashboard_config_t dashboard;
    dolus_metrics_config_t metrics;
    bool daemonize;
    char *pid_file;
    char *config_file;
} dolus_config_t;

dolus_config_t *dolus_config_new(void);
void dolus_config_free(dolus_config_t *config);

dolus_error_t dolus_config_load(dolus_config_t *config, const char *path);
dolus_error_t dolus_config_load_defaults(dolus_config_t *config);
dolus_error_t dolus_config_apply_env(dolus_config_t *config);
dolus_error_t dolus_config_apply_cli(dolus_config_t *config, int argc, char **argv);
dolus_error_t dolus_config_validate(const dolus_config_t *config);

void dolus_config_print(const dolus_config_t *config);

dolus_error_t dolus_config_parse_int(const char *str, int *out);
void dolus_config_free_string_array(char **arr, size_t count);

#ifdef __cplusplus
}
#endif

#endif