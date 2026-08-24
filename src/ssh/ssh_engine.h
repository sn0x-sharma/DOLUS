#ifndef DOLUS_SSH_ENGINE_H
#define DOLUS_SSH_ENGINE_H

#include "../core/dolus.h"
#include "../core/config.h"
#include "../events/event.h"
#include "../events/session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_ssh_engine dolus_ssh_engine_t;
typedef struct dolus_ssh_listener dolus_ssh_listener_t;

typedef void (*dolus_ssh_session_callback)(dolus_session_t *session, void *user_data);
typedef void (*dolus_ssh_event_callback)(const dolus_event_t *event, void *user_data);

dolus_ssh_engine_t *dolus_ssh_engine_new(const dolus_server_config_t *server_config,
                                          const dolus_ssh_config_t *ssh_config,
                                          const dolus_credentials_config_t *cred_config);
void dolus_ssh_engine_free(dolus_ssh_engine_t *engine);

dolus_error_t dolus_ssh_engine_start(dolus_ssh_engine_t *engine,
                                      dolus_ssh_session_callback session_cb,
                                      dolus_ssh_event_callback event_cb,
                                      void *user_data);

dolus_error_t dolus_ssh_engine_stop(dolus_ssh_engine_t *engine);
dolus_error_t dolus_ssh_engine_wait(dolus_ssh_engine_t *engine);

size_t dolus_ssh_engine_active_sessions(const dolus_ssh_engine_t *engine);
size_t dolus_ssh_engine_total_connections(const dolus_ssh_engine_t *engine);

const char *dolus_ssh_banner_profile(const char *profile_name);

#ifdef __cplusplus
}
#endif

#endif