#include "alerting.h"
#include "dolus.h"
#include "config.h"
#include "../events/event.h"
#include "../events/session.h"
#include "../intel/intel.h"
#include "../storage/storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <time.h>
#include <curl/curl.h>

struct dolus_alerting {
    dolus_alerting_config_t config;
    dolus_storage_t *storage;
    dolus_intel_engine_t *intel;
    CURL *curl;
    pthread_mutex_t lock;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    (void)contents; (void)userp;
    return size * nmemb;
}

static dolus_error_t send_webhook(dolus_alerting_t *alerting, const dolus_alert_t *alert) {
    if (!alerting->config.webhook_url || !alerting->curl) return DOLUS_OK;
    
    char *json = NULL;
    asprintf(&json,
             "{\"alert_id\":\"%s\",\"timestamp\":%lld,\"severity\":\"%s\",\"category\":\"%s\","
             "\"source_ip\":\"%s\",\"session_id\":\"%s\",\"message\":\"%s\",\"details\":%s}",
             alert->alert_id, (long long)alert->timestamp_ms, alert->severity, alert->category,
             alert->source_ip ? alert->source_ip : "", alert->session_id ? alert->session_id : "",
             alert->message, alert->details_json ? alert->details_json : "{}");
    
    curl_easy_setopt(alerting->curl, CURLOPT_URL, alerting->config.webhook_url);
    curl_easy_setopt(alerting->curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(alerting->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(alerting->curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(alerting->curl);
    free(json);
    
    return res == CURLE_OK ? DOLUS_OK : DOLUS_ERROR_NETWORK;
}

static dolus_error_t send_syslog(dolus_alerting_t *alerting, const dolus_alert_t *alert) {
    (void)alerting; (void)alert;
    return DOLUS_OK;
}

dolus_alerting_t *dolus_alerting_new(const dolus_alerting_config_t *config,
                                      dolus_storage_t *storage) {
    dolus_alerting_t *alerting = calloc(1, sizeof(dolus_alerting_t));
    if (!alerting) return NULL;
    
    alerting->config = *config;
    alerting->storage = storage;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    alerting->curl = curl_easy_init();
    if (alerting->curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(alerting->curl, CURLOPT_HTTPHEADER, headers);
    }
    
    pthread_mutex_init(&alerting->lock, NULL);
    
    return alerting;
}

void dolus_alerting_free(dolus_alerting_t *alerting) {
    if (!alerting) return;
    
    if (alerting->curl) curl_easy_cleanup(alerting->curl);
    curl_global_cleanup();
    
    pthread_mutex_destroy(&alerting->lock);
    free(alerting);
}

dolus_error_t dolus_alerting_send(dolus_alerting_t *alerting, const dolus_alert_t *alert) {
    if (!alerting || !alert || !alerting->config.enabled) return DOLUS_OK;
    
    pthread_mutex_lock(&alerting->lock);
    
    dolus_error_t err = DOLUS_OK;
    
    if (alerting->config.webhook_url) {
        err = send_webhook(alerting, alert);
    }
    
    if (alerting->config.syslog_enabled) {
        send_syslog(alerting, alert);
    }
    
    pthread_mutex_unlock(&alerting->lock);
    return err;
}

dolus_alert_t *dolus_alert_new(dolus_alert_severity_t severity, const char *category,
                                const char *source_ip, const char *session_id,
                                const char *message, const char *details_json) {
    dolus_alert_t *alert = calloc(1, sizeof(dolus_alert_t));
    if (!alert) return NULL;
    
    uuid_t uuid;
    uuid_generate_random(uuid);
    alert->alert_id = malloc(37);
    uuid_unparse_lower(uuid, alert->alert_id);
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    alert->timestamp_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    
    alert->severity = severity;
    alert->category = strdup(category);
    alert->source_ip = source_ip ? strdup(source_ip) : NULL;
    alert->session_id = session_id ? strdup(session_id) : NULL;
    alert->message = strdup(message);
    alert->details_json = details_json ? strdup(details_json) : strdup("{}");
    
    return alert;
}

void dolus_alert_free(dolus_alert_t *alert) {
    if (!alert) return;
    
    free(alert->alert_id);
    free(alert->category);
    free(alert->source_ip);
    free(alert->session_id);
    free(alert->message);
    free(alert->details_json);
    free(alert);
}

dolus_error_t dolus_alerting_check_thresholds(dolus_alerting_t *alerting,
                                               const dolus_event_t *event,
                                               const dolus_session_t *session,
                                               const dolus_attacker_profile_t *profile) {
    if (!alerting || !alerting->config.enabled) return DOLUS_OK;
    
    if (event && event->event_type == DOLUS_EVENT_AUTHENTICATION_ATTEMPT) {
        if (event->data.auth && event->data.auth->result == DOLUS_AUTH_RESULT_FAILED) {
            if (profile && profile->auth_attempt_count > 100) {
                dolus_alert_t *alert = dolus_alert_new(DOLUS_ALERT_WARNING, "high_auth_volume",
                                                        profile->ip, event->session_id,
                                                        "High authentication attempt volume detected",
                                                        "{\"attempt_count\":100}");
                dolus_alerting_send(alerting, alert);
                dolus_alert_free(alert);
            }
        }
    }
    
    if (session && session->classification) {
        if (session->classification->category == DOLUS_CLASS_BRUTE_FORCE &&
            session->classification->confidence > 0.7) {
            dolus_alert_t *alert = dolus_alert_new(DOLUS_ALERT_WARNING, "brute_force",
                                                    session->source.ip, session->session_id,
                                                    "Brute force attack detected",
                                                    "{\"confidence\":0.7}");
            dolus_alerting_send(alerting, alert);
            dolus_alert_free(alert);
        }
    }
    
    return DOLUS_OK;
}