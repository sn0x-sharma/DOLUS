#include "intel.h"
#include "dolus.h"
#include "config.h"
#include "../events/event.h"
#include "../events/session.h"
#include "../storage/storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <uuid/uuid.h>

#define MAX_ATTACKERS 10000
#define MAX_CAMPAIGNS 1000
#define FINGERPRINT_BUF_SIZE 256

struct dolus_intel_engine {
    dolus_intelligence_config_t config;
    dolus_storage_t *storage;
    
    dolus_attacker_profile_t **attackers;
    size_t attacker_count;
    size_t attacker_capacity;
    
    dolus_campaign_t **campaigns;
    size_t campaign_count;
    size_t campaign_capacity;
    
    dolus_statistics_t *stats;
    pthread_mutex_t lock;
};

static void attacker_profile_free(dolus_attacker_profile_t *profile) {
    if (!profile) return;
    free(profile->ip);
    free(profile->country);
    free(profile->asn);
    for (size_t i = 0; i < profile->username_count; i++) free(profile->usernames[i]);
    free(profile->usernames);
    for (size_t i = 0; i < profile->fingerprint_count; i++) free(profile->fingerprints[i]);
    free(profile->fingerprints);
    free(profile);
}

static void campaign_free(dolus_campaign_t *campaign) {
    if (!campaign) return;
    free(campaign->campaign_id);
    for (size_t i = 0; i < campaign->source_count; i++) free(campaign->source_ips[i]);
    free(campaign->source_ips);
    for (size_t i = 0; i < campaign->username_count; i++) free(campaign->common_usernames[i]);
    free(campaign->common_usernames);
    for (size_t i = 0; i < campaign->fingerprint_count; i++) free(campaign->common_fingerprints[i]);
    free(campaign->common_fingerprints);
    free(campaign);
}

dolus_intel_engine_t *dolus_intel_new(const dolus_intelligence_config_t *config,
                                       dolus_storage_t *storage) {
    dolus_intel_engine_t *engine = calloc(1, sizeof(dolus_intel_engine_t));
    if (!engine) return NULL;
    
    engine->config = *config;
    engine->storage = storage;
    
    engine->attackers = calloc(MAX_ATTACKERS, sizeof(dolus_attacker_profile_t *));
    engine->attacker_capacity = MAX_ATTACKERS;
    
    engine->campaigns = calloc(MAX_CAMPAIGNS, sizeof(dolus_campaign_t *));
    engine->campaign_capacity = MAX_CAMPAIGNS;
    
    engine->stats = calloc(1, sizeof(dolus_statistics_t));
    
    pthread_mutex_init(&engine->lock, NULL);
    
    return engine;
}

void dolus_intel_free(dolus_intel_engine_t *engine) {
    if (!engine) return;
    
    for (size_t i = 0; i < engine->attacker_count; i++) {
        attacker_profile_free(engine->attackers[i]);
    }
    free(engine->attackers);
    
    for (size_t i = 0; i < engine->campaign_count; i++) {
        campaign_free(engine->campaigns[i]);
    }
    free(engine->campaigns);
    
    free(engine->stats);
    pthread_mutex_destroy(&engine->lock);
    free(engine);
}

static dolus_attacker_profile_t *get_or_create_attacker(dolus_intel_engine_t *engine, const char *ip) {
    for (size_t i = 0; i < engine->attacker_count; i++) {
        if (strcmp(engine->attackers[i]->ip, ip) == 0) {
            return engine->attackers[i];
        }
    }
    
    if (engine->attacker_count >= engine->attacker_capacity) return NULL;
    
    dolus_attacker_profile_t *profile = calloc(1, sizeof(dolus_attacker_profile_t));
    profile->ip = strdup(ip);
    profile->usernames = calloc(100, sizeof(char *));
    profile->fingerprints = calloc(50, sizeof(char *));
    
    engine->attackers[engine->attacker_count++] = profile;
    return profile;
}

static void update_attacker_profile(dolus_intel_engine_t *engine, const dolus_session_t *session) {
    dolus_attacker_profile_t *profile = get_or_create_attacker(engine, session->source.ip);
    if (!profile) return;
    
    int64_t now = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    
    if (profile->first_seen_ms == 0 || session->start_time_ms < profile->first_seen_ms) {
        profile->first_seen_ms = session->start_time_ms;
    }
    if (session->end_time_ms > profile->last_seen_ms) {
        profile->last_seen_ms = session->end_time_ms;
    }
    
    profile->session_count++;
    profile->auth_attempt_count += session->auth_attempt_count;
    
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        const dolus_auth_metadata_t *auth = session->auth_attempts[i];
        if (auth->username) {
            bool found = false;
            for (size_t j = 0; j < profile->username_count; j++) {
                if (strcmp(profile->usernames[j], auth->username) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found && profile->username_count < 100) {
                profile->usernames[profile->username_count++] = strdup(auth->username);
            }
        }
    }
    profile->unique_usernames = profile->username_count;
    
    if (session->classification) {
        profile->classifications[session->classification->category]++;
    }
    
    if (session->enrichment) {
        if (session->enrichment->country) {
            free(profile->country);
            profile->country = strdup(session->enrichment->country);
        }
        if (session->enrichment->asn) {
            free(profile->asn);
            profile->asn = strdup(session->enrichment->asn);
        }
        profile->reputation_score = session->enrichment->reputation_score;
    }
}

static char *compute_fingerprint(const dolus_session_t *session) {
    if (!session->connection_meta) return strdup("unknown");
    
    char *fingerprint = malloc(FINGERPRINT_BUF_SIZE);
    if (!fingerprint) return strdup("unknown");
    
    snprintf(fingerprint, FINGERPRINT_BUF_SIZE, "%s|%s|%s|%s|%s|%s",
             session->connection_meta->client_version ? session->connection_meta->client_version : "",
             session->connection_meta->kex_algo ? session->connection_meta->kex_algo : "",
             session->connection_meta->host_key_algo ? session->connection_meta->host_key_algo : "",
             session->connection_meta->cipher_c2s ? session->connection_meta->cipher_c2s : "",
             session->connection_meta->mac_c2s ? session->connection_meta->mac_c2s : "",
             session->connection_meta->compression_c2s ? session->connection_meta->compression_c2s : "");
    
    return fingerprint;
}

static void update_campaigns(dolus_intel_engine_t *engine, const dolus_session_t *session) {
    if (!engine->config.enable_correlation) return;
    
    char *fp = compute_fingerprint(session);
    if (!fp) return;
    
    for (size_t i = 0; i < engine->campaign_count; i++) {
        dolus_campaign_t *campaign = engine->campaigns[i];
        bool fp_match = false;
        for (size_t j = 0; j < campaign->fingerprint_count; j++) {
            if (strcmp(campaign->common_fingerprints[j], fp) == 0) {
                fp_match = true;
                break;
            }
        }
        
        if (fp_match) {
            bool ip_exists = false;
            for (size_t j = 0; j < campaign->source_count; j++) {
                if (strcmp(campaign->source_ips[j], session->source.ip) == 0) {
                    ip_exists = true;
                    break;
                }
            }
            if (!ip_exists && campaign->source_count < 100) {
                campaign->source_ips[campaign->source_count++] = strdup(session->source.ip);
            }
            campaign->session_count++;
            if (session->end_time_ms > campaign->last_seen_ms) {
                campaign->last_seen_ms = session->end_time_ms;
            }
            free(fp);
            return;
        }
    }
    
    if (engine->campaign_count >= engine->campaign_capacity) {
        free(fp);
        return;
    }
    
    dolus_campaign_t *campaign = calloc(1, sizeof(dolus_campaign_t));
    
    uuid_t uuid;
    uuid_generate_random(uuid);
    campaign->campaign_id = malloc(37);
    uuid_unparse_lower(uuid, campaign->campaign_id);
    
    campaign->source_ips = calloc(100, sizeof(char *));
    campaign->source_ips[0] = strdup(session->source.ip);
    campaign->source_count = 1;
    
    campaign->common_fingerprints = calloc(50, sizeof(char *));
    campaign->common_fingerprints[0] = fp;  // Takes ownership
    campaign->fingerprint_count = 1;
    
    campaign->first_seen_ms = session->start_time_ms;
    campaign->last_seen_ms = session->end_time_ms;
    campaign->session_count = 1;
    campaign->confidence = 0.5;
    
    engine->campaigns[engine->campaign_count++] = campaign;
}

static void update_statistics(dolus_intel_engine_t *engine, const dolus_session_t *session) {
    dolus_statistics_t *stats = engine->stats;
    
    stats->total_connections++;
    stats->total_auth_attempts += session->auth_attempt_count;
    
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        if (session->auth_attempts[i]->result == DOLUS_AUTH_RESULT_FAILED) {
            stats->failed_auth_attempts++;
        }
    }
    
    int hour = (session->start_time_ms / 3600000) % 24;
    stats->hourly_counts[hour]++;
    
    int day = (session->start_time_ms / 86400000) % 7;
    stats->daily_counts[day]++;
    
    if (session->classification) {
        stats->classification_counts[session->classification->category]++;
    }
}

dolus_error_t dolus_intel_process_event(dolus_intel_engine_t *engine, const dolus_event_t *event) {
    (void)engine; (void)event;
    return DOLUS_OK;
}

dolus_error_t dolus_intel_process_session(dolus_intel_engine_t *engine, const dolus_session_t *session) {
    if (!engine || !session) return DOLUS_ERROR_INVALID;
    
    pthread_mutex_lock(&engine->lock);
    
    update_attacker_profile(engine, session);
    update_campaigns(engine, session);
    update_statistics(engine, session);
    
    pthread_mutex_unlock(&engine->lock);
    
    return DOLUS_OK;
}

static double classify_score_scanner(const dolus_session_t *session) {
    double score = 0.0;
    
    if (session->auth_attempt_count == 0) score += 0.5;
    if (session->duration_ms < 5000) score += 0.3;
    if (session->connection_meta && session->connection_meta->client_version &&
        strstr(session->connection_meta->client_version, "libssh") != NULL) score += 0.2;
    
    return fmin(score, 1.0);
}

static double classify_score_brute_force(const dolus_session_t *session) {
    double score = 0.0;
    
    if (session->auth_attempt_count > 10) score += 0.4;
    else if (session->auth_attempt_count > 5) score += 0.2;
    
    if (session->duration_ms > 60000 && session->auth_attempt_count > 3) score += 0.3;
    
    int unique_users = 0;
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        bool found = false;
        for (size_t j = 0; j < i; j++) {
            if (session->auth_attempts[i]->username && session->auth_attempts[j]->username &&
                strcmp(session->auth_attempts[i]->username, session->auth_attempts[j]->username) == 0) {
                found = true;
                break;
            }
        }
        if (!found && session->auth_attempts[i]->username) unique_users++;
    }
    if (unique_users == 1 && session->auth_attempt_count > 3) score += 0.3;
    
    return fmin(score, 1.0);
}

static double classify_score_credential_spray(const dolus_session_t *session) {
    double score = 0.0;
    
    int unique_users = 0;
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        bool found = false;
        for (size_t j = 0; j < i; j++) {
            if (session->auth_attempts[i]->username && session->auth_attempts[j]->username &&
                strcmp(session->auth_attempts[i]->username, session->auth_attempts[j]->username) == 0) {
                found = true;
                break;
            }
        }
        if (!found && session->auth_attempts[i]->username) unique_users++;
    }
    
    if (unique_users > 5 && session->auth_attempt_count > unique_users) score += 0.4;
    if (unique_users > 10) score += 0.3;
    if (session->duration_ms < 30000 && unique_users > 3) score += 0.3;
    
    return fmin(score, 1.0);
}

static double classify_score_interactive(const dolus_session_t *session) {
    double score = 0.0;
    
    if (session->auth_attempt_count == 1 && session->auth_attempts[0]->result == DOLUS_AUTH_RESULT_SUCCESS) {
        score += 0.5;
    }
    if (session->duration_ms > 120000) score += 0.3;
    if (session->auth_attempt_count > 0 && session->auth_attempts[0]->method == DOLUS_AUTH_METHOD_PUBLICKEY) {
        score += 0.2;
    }
    
    return fmin(score, 1.0);
}

dolus_classification_metadata_t *dolus_intel_classify_session(dolus_intel_engine_t *engine,
                                                                const dolus_session_t *session) {
    if (!engine || !session) return NULL;
    
    struct {
        dolus_classification_category_t category;
        double score;
        const char *signal;
    } scores[] = {
        {DOLUS_CLASS_SCANNER, classify_score_scanner(session), "no_auth_attempts"},
        {DOLUS_CLASS_BRUTE_FORCE, classify_score_brute_force(session), "high_auth_count"},
        {DOLUS_CLASS_CREDENTIAL_SPRAY, classify_score_credential_spray(session), "many_usernames"},
        {DOLUS_CLASS_INTERACTIVE, classify_score_interactive(session), "successful_auth"},
        {DOLUS_CLASS_UNKNOWN, 0.1, "default"}
    };
    
    double max_score = 0;
    dolus_classification_category_t best = DOLUS_CLASS_UNKNOWN;
    char *signals[10];
    size_t signal_count = 0;
    
    for (size_t i = 0; i < sizeof(scores)/sizeof(scores[0]); i++) {
        if (scores[i].score > max_score) {
            max_score = scores[i].score;
            best = scores[i].category;
        }
        if (scores[i].score > 0.3 && signal_count < 10) {
            signals[signal_count++] = strdup(scores[i].signal);
        }
    }
    
    dolus_classification_metadata_t *result = calloc(1, sizeof(dolus_classification_metadata_t));
    result->category = best;
    result->confidence = max_score;
    result->signals = malloc(signal_count * sizeof(char *));
    result->signal_count = signal_count;
    for (size_t i = 0; i < signal_count; i++) {
        result->signals[i] = signals[i];
    }
    
    return result;
}

dolus_attacker_profile_t *dolus_intel_get_attacker_profile(dolus_intel_engine_t *engine, const char *ip) {
    if (!engine || !ip) return NULL;
    
    pthread_mutex_lock(&engine->lock);
    
    dolus_attacker_profile_t *profile = NULL;
    for (size_t i = 0; i < engine->attacker_count; i++) {
        if (strcmp(engine->attackers[i]->ip, ip) == 0) {
            profile = engine->attackers[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&engine->lock);
    return profile;
}

dolus_attacker_profile_t **dolus_intel_list_attackers(dolus_intel_engine_t *engine, size_t *count, int limit) {
    if (!engine || !count) return NULL;
    
    pthread_mutex_lock(&engine->lock);
    
    size_t n = engine->attacker_count;
    if (limit > 0 && (size_t)limit < n) n = limit;
    
    dolus_attacker_profile_t **list = malloc(n * sizeof(dolus_attacker_profile_t *));
    for (size_t i = 0; i < n; i++) {
        list[i] = engine->attackers[i];
    }
    *count = n;
    
    pthread_mutex_unlock(&engine->lock);
    return list;
}

dolus_campaign_t **dolus_intel_get_campaigns(dolus_intel_engine_t *engine, size_t *count) {
    if (!engine || !count) return NULL;
    
    pthread_mutex_lock(&engine->lock);
    
    dolus_campaign_t **list = malloc(engine->campaign_count * sizeof(dolus_campaign_t *));
    for (size_t i = 0; i < engine->campaign_count; i++) {
        list[i] = engine->campaigns[i];
    }
    *count = engine->campaign_count;
    
    pthread_mutex_unlock(&engine->lock);
    return list;
}

dolus_statistics_t *dolus_intel_get_statistics(dolus_intel_engine_t *engine) {
    if (!engine) return NULL;
    
    pthread_mutex_lock(&engine->lock);
    
    dolus_statistics_t *copy = malloc(sizeof(dolus_statistics_t));
    memcpy(copy, engine->stats, sizeof(dolus_statistics_t));
    
    copy->unique_sources = engine->attacker_count;
    copy->active_sessions = 0;
    
    pthread_mutex_unlock(&engine->lock);
    return copy;
}

void dolus_statistics_free(dolus_statistics_t *stats) {
    if (!stats) return;
    for (int i = 0; i < stats->top_usernames_count; i++) free(stats->top_usernames[i]);
    free(stats->top_usernames);
    free(stats->top_usernames_counts);
    for (int i = 0; i < stats->top_passwords_count; i++) free(stats->top_passwords[i]);
    free(stats->top_passwords);
    free(stats->top_passwords_counts);
    for (int i = 0; i < stats->top_sources_count; i++) free(stats->top_sources[i]);
    free(stats->top_sources);
    free(stats->top_sources_counts);
    free(stats);
}

dolus_error_t dolus_intel_enrich_ip(dolus_intel_engine_t *engine, const char *ip,
                                     dolus_enrichment_metadata_t **enrichment) {
    (void)engine; (void)ip; (void)enrichment;
    return DOLUS_OK;
}

char *dolus_intel_fingerprint_session(const dolus_session_t *session) {
    return compute_fingerprint(session);
}