#ifndef DOLUS_EVENT_H
#define DOLUS_EVENT_H

#include "../core/dolus.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DOLUS_EVENT_CONNECTION_START = 0,
    DOLUS_EVENT_PROTOCOL = 1,
    DOLUS_EVENT_AUTHENTICATION_ATTEMPT = 2,
    DOLUS_EVENT_SESSION = 3,
    DOLUS_EVENT_CONNECTION_END = 4,
    DOLUS_EVENT_CLASSIFICATION = 5,
    DOLUS_EVENT_ENRICHMENT = 6,
    DOLUS_EVENT_ALERT = 7
} dolus_event_type_t;

typedef enum {
    DOLUS_AUTH_METHOD_PASSWORD = 0,
    DOLUS_AUTH_METHOD_PUBLICKEY = 1,
    DOLUS_AUTH_METHOD_KEYBOARD_INTERACTIVE = 2,
    DOLUS_AUTH_METHOD_GSSAPI = 3,
    DOLUS_AUTH_METHOD_NONE = 4,
    DOLUS_AUTH_METHOD_UNKNOWN = 5
} dolus_auth_method_t;

typedef enum {
    DOLUS_AUTH_RESULT_SUCCESS = 0,
    DOLUS_AUTH_RESULT_FAILED = 1,
    DOLUS_AUTH_RESULT_PARTIAL = 2
} dolus_auth_result_t;

typedef enum {
    DOLUS_CLASS_SCANNER = 0,
    DOLUS_CLASS_BRUTE_FORCE = 1,
    DOLUS_CLASS_CREDENTIAL_SPRAY = 2,
    DOLUS_CLASS_DISTRIBUTED = 3,
    DOLUS_CLASS_INTERACTIVE = 4,
    DOLUS_CLASS_UNKNOWN = 5
} dolus_classification_category_t;

typedef struct dolus_source_info {
    char *ip;
    int port;
    int family;  // AF_INET or AF_INET6
} dolus_source_info_t;

typedef struct dolus_auth_metadata {
    dolus_auth_method_t method;
    char *username;
    char *password;  // Only present if policy allows
    char *password_hash;  // SHA-256 hex if policy=hash
    bool password_redacted;
    dolus_auth_result_t result;
    int attempt_number;
} dolus_auth_metadata_t;

typedef struct dolus_classification_metadata {
    dolus_classification_category_t category;
    double confidence;
    char **signals;
    size_t signal_count;
} dolus_classification_metadata_t;

typedef struct dolus_enrichment_metadata {
    char *country;
    char *country_code;
    char *asn;
    char *asn_name;
    double reputation_score;
    bool is_tor;
    bool is_proxy;
    bool is_vpn;
} dolus_enrichment_metadata_t;

typedef struct dolus_alert_metadata {
    char *alert_id;
    char *severity;  // info, warning, critical
    char *category;
    char *message;
    char *details_json;
} dolus_alert_metadata_t;

typedef struct dolus_connection_metadata {
    char *client_version;
    char *server_version;
    char *kex_algo;
    char *host_key_algo;
    char *cipher_c2s;
    char *cipher_s2c;
    char *mac_c2s;
    char *mac_s2c;
    char *compression_c2s;
    char *compression_s2c;
} dolus_connection_metadata_t;

typedef struct dolus_session_metadata {
    int64_t duration_ms;
    int auth_attempt_count;
    char *disconnect_reason;
} dolus_session_metadata_t;

struct dolus_event {
    char *event_id;
    int64_t timestamp_ms;
    char *session_id;
    dolus_event_type_t event_type;
    dolus_source_info_t source;
    union {
        dolus_connection_metadata_t *connection;
        dolus_auth_metadata_t *auth;
        dolus_session_metadata_t *session;
        dolus_classification_metadata_t *classification;
        dolus_enrichment_metadata_t *enrichment;
        dolus_alert_metadata_t *alert;
    } data;
};

dolus_event_t *dolus_event_new(dolus_event_type_t type, const char *session_id,
                                const dolus_source_info_t *source);
void dolus_event_free(dolus_event_t *event);

char *dolus_event_to_json(const dolus_event_t *event);
dolus_error_t dolus_event_from_json(dolus_event_t **event, const char *json);

const char *dolus_event_type_string(dolus_event_type_t type);
const char *dolus_auth_method_string(dolus_auth_method_t method);
const char *dolus_auth_result_string(dolus_auth_result_t result);
const char *dolus_classification_category_string(dolus_classification_category_t cat);

#ifdef __cplusplus
}
#endif

#endif