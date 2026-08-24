#ifndef DOLUS_ALERTING_H
#define DOLUS_ALERTING_H

#include "../core/dolus.h"
#include "../core/config.h"
#include "../events/event.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_alerting dolus_alerting_t;

typedef enum {
    DOLUS_ALERT_INFO = 0,
    DOLUS_ALERT_WARNING = 1,
    DOLUS_ALERT_CRITICAL = 2
} dolus_alert_severity_t;

typedef struct dolus_alert {
    char *alert_id;
    int64_t timestamp_ms;
    dolus_alert_severity_t severity;
    char *category;
    char *source_ip;
    char *session_id;
    char *message;
    char *details_json;
} dolus_alert_t;

dolus_alerting_t *dolus_alerting_new(const dolus_alerting_config_t *config,
                                      dolus_storage_t *storage);
void dolus_alerting_free(dolus_alerting_t *alerting);

dolus_error_t dolus_alerting_send(dolus_alerting_t *alerting, const dolus_alert_t *alert);

dolus_alert_t *dolus_alert_new(dolus_alert_severity_t severity, const char *category,
                                const char *source_ip, const char *session_id,
                                const char *message, const char *details_json);
void dolus_alert_free(dolus_alert_t *alert);

dolus_error_t dolus_alerting_check_thresholds(dolus_alerting_t *alerting,
                                               const dolus_event_t *event,
                                               const dolus_session_t *session,
                                               const dolus_attacker_profile_t *profile);

#ifdef __cplusplus
}
#endif

#endif