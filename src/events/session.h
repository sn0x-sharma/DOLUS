#ifndef DOLUS_SESSION_H
#define DOLUS_SESSION_H

#include "../core/dolus.h"
#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_session_tracker dolus_session_tracker_t;

typedef struct dolus_session {
    char *session_id;
    int64_t start_time_ms;
    int64_t end_time_ms;
    dolus_source_info_t source;
    char *dst_ip;
    int dst_port;
    dolus_connection_metadata_t *connection_meta;
    dolus_auth_metadata_t **auth_attempts;
    size_t auth_attempt_count;
    size_t auth_attempt_capacity;
    dolus_classification_metadata_t *classification;
    dolus_enrichment_metadata_t *enrichment;
    char *disconnect_reason;
    bool active;
} dolus_session_t;

dolus_session_tracker_t *dolus_session_tracker_new(void);
void dolus_session_tracker_free(dolus_session_tracker_t *tracker);

dolus_session_t *dolus_session_create(dolus_session_tracker_t *tracker,
                                       const dolus_source_info_t *source,
                                       const char *dst_ip, int dst_port);
dolus_session_t *dolus_session_get(dolus_session_tracker_t *tracker, const char *session_id);

dolus_error_t dolus_session_add_connection_meta(dolus_session_t *session,
                                                 const dolus_connection_metadata_t *meta);
dolus_error_t dolus_session_add_auth_attempt(dolus_session_t *session,
                                              const dolus_auth_metadata_t *auth);
dolus_error_t dolus_session_set_classification(dolus_session_t *session,
                                                const dolus_classification_metadata_t *classification);
dolus_error_t dolus_session_set_enrichment(dolus_session_t *session,
                                            const dolus_enrichment_metadata_t *enrichment);
dolus_error_t dolus_session_end(dolus_session_t *session, const char *reason);

size_t dolus_session_count(const dolus_session_tracker_t *tracker);
size_t dolus_session_count_active(const dolus_session_tracker_t *tracker);

dolus_session_t **dolus_session_list(const dolus_session_tracker_t *tracker, size_t *count);
dolus_session_t **dolus_session_list_by_source(const dolus_session_tracker_t *tracker,
                                                const char *ip, size_t *count);

void dolus_session_free(dolus_session_t *session);

#ifdef __cplusplus
}
#endif

#endif