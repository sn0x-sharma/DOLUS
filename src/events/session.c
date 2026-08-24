#include "session.h"
#include "event.h"
#include "dolus.h"
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <time.h>

static int64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define INITIAL_SESSION_CAPACITY 1024
#define INITIAL_AUTH_CAPACITY 16

struct dolus_session_tracker {
    dolus_session_t **sessions;
    size_t count;
    size_t capacity;
    pthread_rwlock_t lock;
};

static char *generate_session_id(void) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char *str = malloc(37);
    uuid_unparse_lower(uuid, str);
    return str;
}

static dolus_session_t *session_new(const dolus_source_info_t *source, const char *dst_ip, int dst_port) {
    dolus_session_t *session = calloc(1, sizeof(dolus_session_t));
    if (!session) return NULL;
    
    session->session_id = generate_session_id();
    session->start_time_ms = 0;
    session->end_time_ms = 0;
    session->source = *source;
    session->dst_ip = strdup(dst_ip);
    session->dst_port = dst_port;
    session->auth_attempts = calloc(INITIAL_AUTH_CAPACITY, sizeof(dolus_auth_metadata_t *));
    session->auth_attempt_capacity = INITIAL_AUTH_CAPACITY;
    session->active = true;
    
    return session;
}

dolus_session_tracker_t *dolus_session_tracker_new(void) {
    dolus_session_tracker_t *tracker = calloc(1, sizeof(dolus_session_tracker_t));
    if (!tracker) return NULL;
    
    tracker->sessions = calloc(INITIAL_SESSION_CAPACITY, sizeof(dolus_session_t *));
    tracker->capacity = INITIAL_SESSION_CAPACITY;
    pthread_rwlock_init(&tracker->lock, NULL);
    
    return tracker;
}

void dolus_session_tracker_free(dolus_session_tracker_t *tracker) {
    if (!tracker) return;
    
    for (size_t i = 0; i < tracker->count; i++) {
        dolus_session_free(tracker->sessions[i]);
    }
    free(tracker->sessions);
    pthread_rwlock_destroy(&tracker->lock);
    free(tracker);
}

dolus_session_t *dolus_session_create(dolus_session_tracker_t *tracker,
                                       const dolus_source_info_t *source,
                                       const char *dst_ip, int dst_port) {
    if (!tracker || !source) return NULL;
    
    dolus_session_t *session = session_new(source, dst_ip, dst_port);
    if (!session) return NULL;
    
    session->start_time_ms = 0;
    
    pthread_rwlock_wrlock(&tracker->lock);
    
    if (tracker->count >= tracker->capacity) {
        tracker->capacity *= 2;
        tracker->sessions = realloc(tracker->sessions, tracker->capacity * sizeof(dolus_session_t *));
    }
    
    tracker->sessions[tracker->count++] = session;
    
    pthread_rwlock_unlock(&tracker->lock);
    
    return session;
}

dolus_session_t *dolus_session_get(dolus_session_tracker_t *tracker, const char *session_id) {
    if (!tracker || !session_id) return NULL;
    
    pthread_rwlock_rdlock(&tracker->lock);
    
    for (size_t i = 0; i < tracker->count; i++) {
        if (strcmp(tracker->sessions[i]->session_id, session_id) == 0) {
            pthread_rwlock_unlock(&tracker->lock);
            return tracker->sessions[i];
        }
    }
    
    pthread_rwlock_unlock(&tracker->lock);
    return NULL;
}

dolus_error_t dolus_session_add_connection_meta(dolus_session_t *session,
                                                 const dolus_connection_metadata_t *meta) {
    if (!session || !meta) return DOLUS_ERROR_INVALID;
    
    session->connection_meta = malloc(sizeof(dolus_connection_metadata_t));
    if (!session->connection_meta) return DOLUS_ERROR_NOMEM;
    
    *session->connection_meta = *meta;
    session->connection_meta->client_version = strdup(meta->client_version);
    session->connection_meta->server_version = strdup(meta->server_version);
    session->connection_meta->kex_algo = strdup(meta->kex_algo);
    session->connection_meta->host_key_algo = strdup(meta->host_key_algo);
    session->connection_meta->cipher_c2s = strdup(meta->cipher_c2s);
    session->connection_meta->cipher_s2c = strdup(meta->cipher_s2c);
    session->connection_meta->mac_c2s = strdup(meta->mac_c2s);
    session->connection_meta->mac_s2c = strdup(meta->mac_s2c);
    session->connection_meta->compression_c2s = strdup(meta->compression_c2s);
    session->connection_meta->compression_s2c = strdup(meta->compression_s2c);
    
    return DOLUS_OK;
}

dolus_error_t dolus_session_add_auth_attempt(dolus_session_t *session,
                                              const dolus_auth_metadata_t *auth) {
    if (!session || !auth) return DOLUS_ERROR_INVALID;
    
    if (session->auth_attempt_count >= session->auth_attempt_capacity) {
        session->auth_attempt_capacity *= 2;
        session->auth_attempts = realloc(session->auth_attempts,
                                         session->auth_attempt_capacity * sizeof(dolus_auth_metadata_t *));
    }
    
    dolus_auth_metadata_t *copy = malloc(sizeof(dolus_auth_metadata_t));
    *copy = *auth;
    copy->username = strdup(auth->username);
    copy->password = auth->password ? strdup(auth->password) : NULL;
    copy->password_hash = auth->password_hash ? strdup(auth->password_hash) : NULL;
    
    session->auth_attempts[session->auth_attempt_count++] = copy;
    
    return DOLUS_OK;
}

dolus_error_t dolus_session_set_classification(dolus_session_t *session,
                                                const dolus_classification_metadata_t *classification) {
    if (!session || !classification) return DOLUS_ERROR_INVALID;
    
    session->classification = malloc(sizeof(dolus_classification_metadata_t));
    *session->classification = *classification;
    session->classification->signals = malloc(classification->signal_count * sizeof(char *));
    for (size_t i = 0; i < classification->signal_count; i++) {
        session->classification->signals[i] = strdup(classification->signals[i]);
    }
    
    return DOLUS_OK;
}

dolus_error_t dolus_session_set_enrichment(dolus_session_t *session,
                                            const dolus_enrichment_metadata_t *enrichment) {
    if (!session || !enrichment) return DOLUS_ERROR_INVALID;
    
    session->enrichment = malloc(sizeof(dolus_enrichment_metadata_t));
    *session->enrichment = *enrichment;
    session->enrichment->country = strdup(enrichment->country);
    session->enrichment->country_code = strdup(enrichment->country_code);
    session->enrichment->asn = strdup(enrichment->asn);
    session->enrichment->asn_name = strdup(enrichment->asn_name);
    
    return DOLUS_OK;
}

dolus_error_t dolus_session_end(dolus_session_t *session, const char *reason) {
    if (!session) return DOLUS_ERROR_INVALID;
    
    session->end_time_ms = current_time_ms();
    session->duration_ms = session->end_time_ms - session->start_time_ms;
    session->disconnect_reason = strdup(reason ? reason : "unknown");
    session->active = false;
    
    return DOLUS_OK;
}

size_t dolus_session_count(const dolus_session_tracker_t *tracker) {
    if (!tracker) return 0;
    pthread_rwlock_rdlock(&tracker->lock);
    size_t count = tracker->count;
    pthread_rwlock_unlock(&tracker->lock);
    return count;
}

size_t dolus_session_count_active(const dolus_session_tracker_t *tracker) {
    if (!tracker) return 0;
    
    pthread_rwlock_rdlock(&tracker->lock);
    size_t active = 0;
    for (size_t i = 0; i < tracker->count; i++) {
        if (tracker->sessions[i]->active) active++;
    }
    pthread_rwlock_unlock(&tracker->lock);
    return active;
}

dolus_session_t **dolus_session_list(const dolus_session_tracker_t *tracker, size_t *count) {
    if (!tracker || !count) return NULL;
    
    pthread_rwlock_rdlock(&tracker->lock);
    
    dolus_session_t **list = malloc(tracker->count * sizeof(dolus_session_t *));
    for (size_t i = 0; i < tracker->count; i++) {
        list[i] = tracker->sessions[i];
    }
    *count = tracker->count;
    
    pthread_rwlock_unlock(&tracker->lock);
    return list;
}

dolus_session_t **dolus_session_list_by_source(const dolus_session_tracker_t *tracker,
                                                const char *ip, size_t *count) {
    if (!tracker || !ip || !count) return NULL;
    
    pthread_rwlock_rdlock(&tracker->lock);
    
    size_t matches = 0;
    for (size_t i = 0; i < tracker->count; i++) {
        if (strcmp(tracker->sessions[i]->source.ip, ip) == 0) matches++;
    }
    
    dolus_session_t **list = malloc(matches * sizeof(dolus_session_t *));
    size_t idx = 0;
    for (size_t i = 0; i < tracker->count; i++) {
        if (strcmp(tracker->sessions[i]->source.ip, ip) == 0) {
            list[idx++] = tracker->sessions[i];
        }
    }
    *count = matches;
    
    pthread_rwlock_unlock(&tracker->lock);
    return list;
}

void dolus_session_free(dolus_session_t *session) {
    if (!session) return;
    
    free(session->session_id);
    free(session->dst_ip);
    free(session->disconnect_reason);
    
    if (session->connection_meta) {
        free(session->connection_meta->client_version);
        free(session->connection_meta->server_version);
        free(session->connection_meta->kex_algo);
        free(session->connection_meta->host_key_algo);
        free(session->connection_meta->cipher_c2s);
        free(session->connection_meta->cipher_s2c);
        free(session->connection_meta->mac_c2s);
        free(session->connection_meta->mac_s2c);
        free(session->connection_meta->compression_c2s);
        free(session->connection_meta->compression_s2c);
        free(session->connection_meta);
    }
    
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        free(session->auth_attempts[i]->username);
        free(session->auth_attempts[i]->password);
        free(session->auth_attempts[i]->password_hash);
        free(session->auth_attempts[i]);
    }
    free(session->auth_attempts);
    
    if (session->classification) {
        for (size_t i = 0; i < session->classification->signal_count; i++) {
            free(session->classification->signals[i]);
        }
        free(session->classification->signals);
        free(session->classification);
    }
    
    if (session->enrichment) {
        free(session->enrichment->country);
        free(session->enrichment->country_code);
        free(session->enrichment->asn);
        free(session->enrichment->asn_name);
        free(session->enrichment);
    }
    
    free(session);
}