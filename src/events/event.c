#include "event.h"
#include "dolus.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <time.h>
#include <json-c/json.h>

static char *generate_uuid(void) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char *str = malloc(37);
    uuid_unparse_lower(uuid, str);
    return str;
}

static int64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

dolus_event_t *dolus_event_new(dolus_event_type_t type, const char *session_id,
                                const dolus_source_info_t *source) {
    dolus_event_t *event = calloc(1, sizeof(dolus_event_t));
    if (!event) return NULL;
    
    event->event_id = generate_uuid();
    event->timestamp_ms = current_time_ms();
    event->session_id = strdup(session_id ? session_id : "");
    event->event_type = type;
    
    if (source) {
        event->source.ip = strdup(source->ip ? source->ip : "");
        event->source.port = source->port;
        event->source.family = source->family;
    }
    
    return event;
}

void dolus_event_free(dolus_event_t *event) {
    if (!event) return;
    
    free(event->event_id);
    free(event->session_id);
    free(event->source.ip);
    
    switch (event->event_type) {
        case DOLUS_EVENT_CONNECTION_START:
        case DOLUS_EVENT_PROTOCOL:
            if (event->data.connection) {
                free(event->data.connection->client_version);
                free(event->data.connection->server_version);
                free(event->data.connection->kex_algo);
                free(event->data.connection->host_key_algo);
                free(event->data.connection->cipher_c2s);
                free(event->data.connection->cipher_s2c);
                free(event->data.connection->mac_c2s);
                free(event->data.connection->mac_s2c);
                free(event->data.connection->compression_c2s);
                free(event->data.connection->compression_s2c);
                free(event->data.connection);
            }
            break;
        case DOLUS_EVENT_AUTHENTICATION_ATTEMPT:
            if (event->data.auth) {
                free(event->data.auth->username);
                free(event->data.auth->password);
                free(event->data.auth->password_hash);
                free(event->data.auth);
            }
            break;
        case DOLUS_EVENT_SESSION:
        case DOLUS_EVENT_CONNECTION_END:
            if (event->data.session) {
                free(event->data.session->disconnect_reason);
                free(event->data.session);
            }
            break;
        case DOLUS_EVENT_CLASSIFICATION:
            if (event->data.classification) {
                for (size_t i = 0; i < event->data.classification->signal_count; i++) {
                    free(event->data.classification->signals[i]);
                }
                free(event->data.classification->signals);
                free(event->data.classification);
            }
            break;
        case DOLUS_EVENT_ENRICHMENT:
            if (event->data.enrichment) {
                free(event->data.enrichment->country);
                free(event->data.enrichment->country_code);
                free(event->data.enrichment->asn);
                free(event->data.enrichment->asn_name);
                free(event->data.enrichment);
            }
            break;
        case DOLUS_EVENT_ALERT:
            if (event->data.alert) {
                free(event->data.alert->alert_id);
                free(event->data.alert->severity);
                free(event->data.alert->category);
                free(event->data.alert->message);
                free(event->data.alert->details_json);
                free(event->data.alert);
            }
            break;
    }
    
    free(event);
}

static void json_add_string(json_object *obj, const char *key, const char *val) {
    if (val) json_object_object_add(obj, key, json_object_new_string(val));
}

static void json_add_int(json_object *obj, const char *key, int64_t val) {
    json_object_object_add(obj, key, json_object_new_int64(val));
}

static void json_add_double(json_object *obj, const char *key, double val) {
    json_object_object_add(obj, key, json_object_new_double(val));
}

static void json_add_bool(json_object *obj, const char *key, bool val) {
    json_object_object_add(obj, key, json_object_new_boolean(val));
}

static json_object *source_to_json(const dolus_source_info_t *src) {
    json_object *obj = json_object_new_object();
    json_add_string(obj, "ip", src->ip);
    json_add_int(obj, "port", src->port);
    json_add_int(obj, "family", src->family);
    return obj;
}

char *dolus_event_to_json(const dolus_event_t *event) {
    if (!event) return NULL;
    
    json_object *root = json_object_new_object();
    json_add_string(root, "event_id", event->event_id);
    json_add_int(root, "timestamp", event->timestamp_ms);
    json_add_string(root, "session_id", event->session_id);
    json_add_string(root, "event_type", dolus_event_type_string(event->event_type));
    json_object_object_add(root, "source", source_to_json(&event->source));
    
    switch (event->event_type) {
        case DOLUS_EVENT_CONNECTION_START:
        case DOLUS_EVENT_PROTOCOL: {
            if (event->data.connection) {
                json_object *conn = json_object_new_object();
                json_add_string(conn, "client_version", event->data.connection->client_version);
                json_add_string(conn, "server_version", event->data.connection->server_version);
                json_add_string(conn, "kex_algo", event->data.connection->kex_algo);
                json_add_string(conn, "host_key_algo", event->data.connection->host_key_algo);
                json_add_string(conn, "cipher_c2s", event->data.connection->cipher_c2s);
                json_add_string(conn, "cipher_s2c", event->data.connection->cipher_s2c);
                json_add_string(conn, "mac_c2s", event->data.connection->mac_c2s);
                json_add_string(conn, "mac_s2c", event->data.connection->mac_s2c);
                json_add_string(conn, "compression_c2s", event->data.connection->compression_c2s);
                json_add_string(conn, "compression_s2c", event->data.connection->compression_s2c);
                json_object_object_add(root, "connection", conn);
            }
            break;
        }
        case DOLUS_EVENT_AUTHENTICATION_ATTEMPT: {
            if (event->data.auth) {
                json_object *auth = json_object_new_object();
                json_add_string(auth, "method", dolus_auth_method_string(event->data.auth->method));
                json_add_string(auth, "username", event->data.auth->username);
                if (event->data.auth->password && !event->data.auth->password_redacted) {
                    json_add_string(auth, "password", event->data.auth->password);
                }
                json_add_string(auth, "password_hash", event->data.auth->password_hash);
                json_add_bool(auth, "password_redacted", event->data.auth->password_redacted);
                json_add_string(auth, "result", dolus_auth_result_string(event->data.auth->result));
                json_add_int(auth, "attempt_number", event->data.auth->attempt_number);
                json_object_object_add(root, "authentication", auth);
            }
            break;
        }
        case DOLUS_EVENT_SESSION:
        case DOLUS_EVENT_CONNECTION_END: {
            if (event->data.session) {
                json_object *sess = json_object_new_object();
                json_add_int(sess, "duration_ms", event->data.session->duration_ms);
                json_add_int(sess, "auth_attempt_count", event->data.session->auth_attempt_count);
                json_add_string(sess, "disconnect_reason", event->data.session->disconnect_reason);
                json_object_object_add(root, "session", sess);
            }
            break;
        }
        case DOLUS_EVENT_CLASSIFICATION: {
            if (event->data.classification) {
                json_object *cls = json_object_new_object();
                json_add_string(cls, "category", dolus_classification_category_string(event->data.classification->category));
                json_add_double(cls, "confidence", event->data.classification->confidence);
                json_object *signals = json_object_new_array();
                for (size_t i = 0; i < event->data.classification->signal_count; i++) {
                    json_object_array_add(signals, json_object_new_string(event->data.classification->signals[i]));
                }
                json_object_object_add(cls, "signals", signals);
                json_object_object_add(root, "classification", cls);
            }
            break;
        }
        case DOLUS_EVENT_ENRICHMENT: {
            if (event->data.enrichment) {
                json_object *enr = json_object_new_object();
                json_add_string(enr, "country", event->data.enrichment->country);
                json_add_string(enr, "country_code", event->data.enrichment->country_code);
                json_add_string(enr, "asn", event->data.enrichment->asn);
                json_add_string(enr, "asn_name", event->data.enrichment->asn_name);
                json_add_double(enr, "reputation_score", event->data.enrichment->reputation_score);
                json_add_bool(enr, "is_tor", event->data.enrichment->is_tor);
                json_add_bool(enr, "is_proxy", event->data.enrichment->is_proxy);
                json_add_bool(enr, "is_vpn", event->data.enrichment->is_vpn);
                json_object_object_add(root, "enrichment", enr);
            }
            break;
        }
        case DOLUS_EVENT_ALERT: {
            if (event->data.alert) {
                json_object *alt = json_object_new_object();
                json_add_string(alt, "alert_id", event->data.alert->alert_id);
                json_add_string(alt, "severity", event->data.alert->severity);
                json_add_string(alt, "category", event->data.alert->category);
                json_add_string(alt, "message", event->data.alert->message);
                json_add_string(alt, "details", event->data.alert->details_json);
                json_object_object_add(root, "alert", alt);
            }
            break;
        }
    }
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);
    json_object_put(root);
    return result;
}

dolus_error_t dolus_event_from_json(dolus_event_t **event, const char *json) {
    (void)event; (void)json;
    return DOLUS_ERROR_INVALID;
}

const char *dolus_event_type_string(dolus_event_type_t type) {
    static const char *strings[] = {
        "connection_start", "protocol", "authentication_attempt",
        "session", "connection_end", "classification", "enrichment", "alert"
    };
    if (type >= 0 && type < 8) return strings[type];
    return "unknown";
}

const char *dolus_auth_method_string(dolus_auth_method_t method) {
    static const char *strings[] = {
        "password", "publickey", "keyboard_interactive", "gssapi", "none", "unknown"
    };
    if (method >= 0 && method < 6) return strings[method];
    return "unknown";
}

const char *dolus_auth_result_string(dolus_auth_result_t result) {
    static const char *strings[] = {"success", "failed", "partial"};
    if (result >= 0 && result < 3) return strings[result];
    return "unknown";
}

const char *dolus_classification_category_string(dolus_classification_category_t cat) {
    static const char *strings[] = {
        "scanner", "brute_force", "credential_spray", "distributed", "interactive", "unknown"
    };
    if (cat >= 0 && cat < 6) return strings[cat];
    return "unknown";
}