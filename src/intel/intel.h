#ifndef DOLUS_INTEL_H
#define DOLUS_INTEL_H

#include "../core/dolus.h"
#include "../events/event.h"
#include "../events/session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_intel_engine dolus_intel_engine_t;

typedef struct dolus_attacker_profile {
    char *ip;
    int64_t first_seen_ms;
    int64_t last_seen_ms;
    int session_count;
    int auth_attempt_count;
    int unique_usernames;
    char **usernames;
    size_t username_count;
    int classifications[6];  // One per dolus_classification_category_t
    char *country;
    char *asn;
    double reputation_score;
    char **fingerprints;
    size_t fingerprint_count;
} dolus_attacker_profile_t;

typedef struct dolus_campaign {
    char *campaign_id;
    char **source_ips;
    size_t source_count;
    int64_t first_seen_ms;
    int64_t last_seen_ms;
    int session_count;
    char **common_usernames;
    size_t username_count;
    char **common_fingerprints;
    size_t fingerprint_count;
    double confidence;
} dolus_campaign_t;

typedef struct dolus_statistics {
    int64_t total_connections;
    int64_t unique_sources;
    int64_t total_auth_attempts;
    int64_t failed_auth_attempts;
    int64_t active_sessions;
    int64_t sessions_last_hour;
    int64_t sessions_last_24h;
    int64_t sessions_last_7d;
    int top_usernames_count;
    char **top_usernames;
    int *top_usernames_counts;
    int top_passwords_count;
    char **top_passwords;
    int *top_passwords_counts;
    int top_sources_count;
    char **top_sources;
    int *top_sources_counts;
    int classification_counts[6];
    int hourly_counts[24];
    int daily_counts[7];
} dolus_statistics_t;

dolus_intel_engine_t *dolus_intel_new(const dolus_intelligence_config_t *config,
                                       dolus_storage_t *storage);
void dolus_intel_free(dolus_intel_engine_t *engine);

dolus_error_t dolus_intel_process_event(dolus_intel_engine_t *engine, const dolus_event_t *event);
dolus_error_t dolus_intel_process_session(dolus_intel_engine_t *engine, const dolus_session_t *session);

dolus_classification_metadata_t *dolus_intel_classify_session(dolus_intel_engine_t *engine,
                                                                const dolus_session_t *session);

dolus_attacker_profile_t *dolus_intel_get_attacker_profile(dolus_intel_engine_t *engine, const char *ip);
dolus_attacker_profile_t **dolus_intel_list_attackers(dolus_intel_engine_t *engine, size_t *count, int limit);

dolus_campaign_t **dolus_intel_get_campaigns(dolus_intel_engine_t *engine, size_t *count);

dolus_statistics_t *dolus_intel_get_statistics(dolus_intel_engine_t *engine);
void dolus_statistics_free(dolus_statistics_t *stats);

dolus_error_t dolus_intel_enrich_ip(dolus_intel_engine_t *engine, const char *ip,
                                     dolus_enrichment_metadata_t **enrichment);

char *dolus_intel_fingerprint_session(const dolus_session_t *session);

#ifdef __cplusplus
}
#endif

#endif