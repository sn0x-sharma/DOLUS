#include "storage.h"
#include "dolus.h"
#include "config.h"
#include "logging.h"
#include "../events/event.h"
#include "../events/session.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <json-c/json.h>

struct dolus_storage {
    dolus_storage_config_t config;
    dolus_credentials_config_t cred_config;
    dolus_logger_t *text_logger;
    dolus_logger_t *json_logger;
    sqlite3 *db;
    pthread_mutex_t db_mutex;
    bool initialized;
};

static const char *SQLITE_SCHEMA = 
    "CREATE TABLE IF NOT EXISTS sessions ("
    "    session_id TEXT PRIMARY KEY,"
    "    start_time INTEGER NOT NULL,"
    "    end_time INTEGER,"
    "    duration_ms INTEGER,"
    "    src_ip TEXT NOT NULL,"
    "    src_port INTEGER NOT NULL,"
    "    dst_ip TEXT NOT NULL,"
    "    dst_port INTEGER NOT NULL,"
    "    client_version TEXT,"
    "    server_version TEXT,"
    "    kex_algo TEXT,"
    "    host_key_algo TEXT,"
    "    classification_category TEXT,"
    "    classification_confidence REAL,"
    "    signals TEXT,"
    "    created_at INTEGER DEFAULT (strftime('%s','now')*1000)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);"
    "CREATE INDEX IF NOT EXISTS idx_sessions_classification ON sessions(classification_category);"
    ""
    "CREATE TABLE IF NOT EXISTS auth_events ("
    "    event_id TEXT PRIMARY KEY,"
    "    session_id TEXT NOT NULL REFERENCES sessions(session_id),"
    "    timestamp INTEGER NOT NULL,"
    "    method TEXT NOT NULL,"
    "    username TEXT,"
    "    password_hash TEXT,"
    "    password_redacted INTEGER DEFAULT 1,"
    "    result TEXT NOT NULL,"
    "    attempt_number INTEGER NOT NULL,"
    "    created_at INTEGER DEFAULT (strftime('%s','now')*1000)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_events(session_id);"
    "CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_events(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_events(username);"
    ""
    "CREATE TABLE IF NOT EXISTS source_profiles ("
    "    src_ip TEXT PRIMARY KEY,"
    "    first_seen INTEGER NOT NULL,"
    "    last_seen INTEGER NOT NULL,"
    "    session_count INTEGER DEFAULT 0,"
    "    auth_attempt_count INTEGER DEFAULT 0,"
    "    unique_usernames INTEGER DEFAULT 0,"
    "    classifications TEXT,"
    "    country TEXT,"
    "    asn TEXT,"
    "    reputation_score REAL,"
    "    updated_at INTEGER DEFAULT (strftime('%s','now')*1000)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_source_last_seen ON source_profiles(last_seen);"
    ""
    "CREATE TABLE IF NOT EXISTS enrichment_cache ("
    "    ip TEXT PRIMARY KEY,"
    "    country TEXT,"
    "    asn TEXT,"
    "    reputation_score REAL,"
    "    fetched_at INTEGER NOT NULL,"
    "    expires_at INTEGER NOT NULL"
    ");"
    ""
    "CREATE TABLE IF NOT EXISTS alerts ("
    "    alert_id TEXT PRIMARY KEY,"
    "    timestamp INTEGER NOT NULL,"
    "    severity TEXT NOT NULL,"
    "    category TEXT NOT NULL,"
    "    source_ip TEXT,"
    "    session_id TEXT,"
    "    message TEXT NOT NULL,"
    "    details TEXT,"
    "    acknowledged INTEGER DEFAULT 0,"
    "    created_at INTEGER DEFAULT (strftime('%s','now')*1000)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);";

static dolus_error_t init_sqlite(dolus_storage_t *storage) {
    if (!storage->config.enable_sqlite) return DOLUS_OK;
    
    int rc = sqlite3_open_v2(storage->config.sqlite_path, &storage->db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        return DOLUS_ERROR_DB;
    }
    
    sqlite3_busy_timeout(storage->db, 5000);
    
    char *errmsg = NULL;
    rc = sqlite3_exec(storage->db, SQLITE_SCHEMA, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
        sqlite3_close(storage->db);
        storage->db = NULL;
        return DOLUS_ERROR_DB;
    }
    
    pthread_mutex_init(&storage->db_mutex, NULL);
    return DOLUS_OK;
}

static void close_sqlite(dolus_storage_t *storage) {
    if (storage->db) {
        sqlite3_close(storage->db);
        storage->db = NULL;
    }
    pthread_mutex_destroy(&storage->db_mutex);
}

dolus_storage_t *dolus_storage_new(const dolus_storage_config_t *config,
                                    const dolus_credentials_config_t *cred_config) {
    dolus_storage_t *storage = calloc(1, sizeof(dolus_storage_t));
    if (!storage) return NULL;
    
    storage->config = *config;
    storage->cred_config = *cred_config;
    
    return storage;
}

void dolus_storage_free(dolus_storage_t *storage) {
    if (!storage) return;
    
    if (storage->text_logger) dolus_logger_free(storage->text_logger);
    if (storage->json_logger) dolus_logger_free(storage->json_logger);
    close_sqlite(storage);
    free(storage);
}

dolus_error_t dolus_storage_init(dolus_storage_t *storage) {
    if (!storage || storage->initialized) return DOLUS_ERROR_INVALID;
    
    if (storage->config.enable_text_logs) {
        dolus_logging_config_t log_config = {
            .level = DOLUS_LOG_INFO,
            .format = DOLUS_LOG_FORMAT_TEXT,
            .outputs = (char*[]){"file"},
            .output_count = 1,
            .file_path = storage->config.sqlite_path ? 
                strdup(storage->config.sqlite_path) : strdup("dolus.log"),
            .max_size_mb = 100,
            .max_files = 10,
            .console_output = false
        };
        storage->text_logger = dolus_logger_new(&log_config);
    }
    
    if (storage->config.enable_json_logs) {
        dolus_logging_config_t log_config = {
            .level = DOLUS_LOG_INFO,
            .format = DOLUS_LOG_FORMAT_JSON,
            .outputs = (char*[]){"file"},
            .output_count = 1,
            .file_path = storage->config.sqlite_path ? 
                strdup(storage->config.sqlite_path) : strdup("dolus.json"),
            .max_size_mb = 100,
            .max_files = 10,
            .console_output = false
        };
        storage->json_logger = dolus_logger_new(&log_config);
    }
    
    dolus_error_t err = init_sqlite(storage);
    if (err != DOLUS_OK) return err;
    
    storage->initialized = true;
    return DOLUS_OK;
}

static dolus_error_t write_session_sqlite(dolus_storage_t *storage, const dolus_session_t *session) {
    if (!storage->db) return DOLUS_OK;
    
    pthread_mutex_lock(&storage->db_mutex);
    
    sqlite3_stmt *stmt;
    const char *sql = "INSERT OR REPLACE INTO sessions "
                      "(session_id, start_time, end_time, duration_ms, src_ip, src_port, dst_ip, dst_port, "
                      " client_version, server_version, kex_algo, host_key_algo, "
                      " classification_category, classification_confidence, signals) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&storage->db_mutex);
        return DOLUS_ERROR_DB;
    }
    
    char *signals_json = NULL;
    if (session->classification && session->classification->signal_count > 0) {
        // Build JSON array of signals
        json_object *signals_arr = json_object_new_array();
        for (size_t i = 0; i < session->classification->signal_count; i++) {
            json_object_array_add(signals_arr, json_object_new_string(session->classification->signals[i]));
        }
        const char *json_str = json_object_to_json_string(signals_arr);
        signals_json = strdup(json_str);
        json_object_put(signals_arr);
    }
    
    sqlite3_bind_text(stmt, 1, session->session_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, session->start_time_ms);
    sqlite3_bind_int64(stmt, 3, session->end_time_ms);
    sqlite3_bind_int64(stmt, 4, session->duration_ms);
    sqlite3_bind_text(stmt, 5, session->source.ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, session->source.port);
    sqlite3_bind_text(stmt, 7, session->dst_ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 8, session->dst_port);
    sqlite3_bind_text(stmt, 9, session->connection_meta ? session->connection_meta->client_version : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, session->connection_meta ? session->connection_meta->server_version : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, session->connection_meta ? session->connection_meta->kex_algo : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, session->connection_meta ? session->connection_meta->host_key_algo : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 13, session->classification ? dolus_classification_category_string(session->classification->category) : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 14, session->classification ? session->classification->confidence : 0.0);
    sqlite3_bind_text(stmt, 15, signals_json ? signals_json : NULL, -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    free(signals_json);
    pthread_mutex_unlock(&storage->db_mutex);
    
    return rc == SQLITE_DONE ? DOLUS_OK : DOLUS_ERROR_DB;
}

static dolus_error_t write_auth_events_sqlite(dolus_storage_t *storage, const dolus_session_t *session) {
    if (!storage->db) return DOLUS_OK;
    
    pthread_mutex_lock(&storage->db_mutex);
    
    sqlite3_stmt *stmt;
    const char *sql = "INSERT OR REPLACE INTO auth_events "
                      "(event_id, session_id, timestamp, method, username, password_hash, password_redacted, result, attempt_number) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    int rc = sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&storage->db_mutex);
        return DOLUS_ERROR_DB;
    }
    
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        const dolus_auth_metadata_t *auth = session->auth_attempts[i];
        
        uuid_t uuid;
        uuid_generate_random(uuid);
        char event_id[37];
        uuid_unparse_lower(uuid, event_id);
        
        sqlite3_bind_text(stmt, 1, event_id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, session->session_id, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, session->start_time_ms + i * 1000);
        sqlite3_bind_text(stmt, 4, dolus_auth_method_string(auth->method), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, auth->username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, auth->password_hash, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, auth->password_redacted ? 1 : 0);
        sqlite3_bind_text(stmt, 8, dolus_auth_result_string(auth->result), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 9, auth->attempt_number);
        
        rc = sqlite3_step(stmt);
        sqlite3_reset(stmt);
        
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&storage->db_mutex);
            return DOLUS_ERROR_DB;
        }
    }
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&storage->db_mutex);
    return DOLUS_OK;
}

dolus_error_t dolus_storage_write_event(dolus_storage_t *storage, const dolus_event_t *event) {
    if (!storage || !event || !storage->initialized) return DOLUS_ERROR_INVALID;
    
    if (storage->config.enable_text_logs && storage->text_logger) {
        dolus_logger_log_event(storage->text_logger, event);
    }
    
    if (storage->config.enable_json_logs && storage->json_logger) {
        dolus_logger_log_event(storage->json_logger, event);
    }
    
    return DOLUS_OK;
}

dolus_error_t dolus_storage_write_session(dolus_storage_t *storage, const void *session_ptr) {
    if (!storage || !session_ptr || !storage->initialized) return DOLUS_ERROR_INVALID;
    
    const dolus_session_t *session = session_ptr;
    
    dolus_error_t err = write_session_sqlite(storage, session);
    if (err != DOLUS_OK) return err;
    
    err = write_auth_events_sqlite(storage, session);
    if (err != DOLUS_OK) return err;
    
    return DOLUS_OK;
}

dolus_error_t dolus_storage_flush(dolus_storage_t *storage) {
    if (!storage) return DOLUS_ERROR_INVALID;
    
    if (storage->text_logger && storage->text_logger->file_handle) {
        fflush(storage->text_logger->file_handle);
    }
    if (storage->json_logger && storage->json_logger->file_handle) {
        fflush(storage->json_logger->file_handle);
    }
    
    return DOLUS_OK;
}

dolus_error_t dolus_storage_rotate(dolus_storage_t *storage) {
    if (!storage) return DOLUS_ERROR_INVALID;
    
    if (storage->text_logger) dolus_logger_rotate(storage->text_logger);
    if (storage->json_logger) dolus_logger_rotate(storage->json_logger);
    
    return DOLUS_OK;
}

dolus_error_t dolus_storage_retention(dolus_storage_t *storage) {
    if (!storage || !storage->db) return DOLUS_OK;
    
    pthread_mutex_lock(&storage->db_mutex);
    
    int64_t cutoff = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    cutoff = (ts.tv_sec - storage->config.retention_days * 86400) * 1000;
    
    char sql[512];
    snprintf(sql, sizeof(sql), "DELETE FROM sessions WHERE start_time < %lld", (long long)cutoff);
    sqlite3_exec(storage->db, sql, NULL, NULL, NULL);
    
    snprintf(sql, sizeof(sql), "DELETE FROM auth_events WHERE timestamp < %lld", (long long)cutoff);
    sqlite3_exec(storage->db, sql, NULL, NULL, NULL);
    
    snprintf(sql, sizeof(sql), "DELETE FROM alerts WHERE timestamp < %lld", (long long)cutoff);
    sqlite3_exec(storage->db, sql, NULL, NULL, NULL);
    
    pthread_mutex_unlock(&storage->db_mutex);
    
    return DOLUS_OK;
}

dolus_error_t dolus_storage_query_sessions(dolus_storage_t *storage, const char *query,
                                            void (*callback)(const void *session, void *ctx), void *ctx) {
    (void)storage; (void)query; (void)callback; (void)ctx;
    return DOLUS_ERROR_INVALID;
}

dolus_error_t dolus_storage_query_events(dolus_storage_t *storage, const char *query,
                                          void (*callback)(const dolus_event_t *event, void *ctx), void *ctx) {
    (void)storage; (void)query; (void)callback; (void)ctx;
    return DOLUS_ERROR_INVALID;
}

dolus_error_t dolus_storage_get_stats(dolus_storage_t *storage, void *stats) {
    (void)storage; (void)stats;
    return DOLUS_ERROR_INVALID;
}