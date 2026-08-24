#ifndef DOLUS_STORAGE_H
#define DOLUS_STORAGE_H

#include "../core/dolus.h"
#include "../core/config.h"
#include "../events/event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_storage dolus_storage_t;

dolus_storage_t *dolus_storage_new(const dolus_storage_config_t *config,
                                    const dolus_credentials_config_t *cred_config);
void dolus_storage_free(dolus_storage_t *storage);

dolus_error_t dolus_storage_init(dolus_storage_t *storage);
dolus_error_t dolus_storage_write_event(dolus_storage_t *storage, const dolus_event_t *event);
dolus_error_t dolus_storage_write_session(dolus_storage_t *storage, const void *session);
dolus_error_t dolus_storage_flush(dolus_storage_t *storage);
dolus_error_t dolus_storage_rotate(dolus_storage_t *storage);
dolus_error_t dolus_storage_retention(dolus_storage_t *storage);

dolus_error_t dolus_storage_query_sessions(dolus_storage_t *storage, const char *query,
                                            void (*callback)(const void *session, void *ctx), void *ctx);
dolus_error_t dolus_storage_query_events(dolus_storage_t *storage, const char *query,
                                          void (*callback)(const dolus_event_t *event, void *ctx), void *ctx);
dolus_error_t dolus_storage_get_stats(dolus_storage_t *storage, void *stats);

#ifdef __cplusplus
}
#endif

#endif