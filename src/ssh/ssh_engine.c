#include "ssh_engine.h"
#include "dolus.h"
#include "config.h"
#include "logging.h"
#include "../events/event.h"
#include "../events/session.h"
#include "../storage/storage.h"
#include "../intel/intel.h"
#include "../alerting/alerting.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <time.h>
#include <openssl/sha.h>

struct dolus_ssh_listener {
    ssh_bind bind;
    char *bind_addr;
    int port;
    int sock;
    bool running;
    pthread_t thread;
    dolus_ssh_engine_t *engine;
};

struct dolus_ssh_engine {
    dolus_server_config_t server_config;
    dolus_ssh_config_t ssh_config;
    dolus_credentials_config_t cred_config;
    
    dolus_ssh_listener_t **listeners;
    size_t listener_count;
    
    dolus_ssh_session_callback session_cb;
    dolus_ssh_event_callback event_cb;
    void *user_data;
    
    dolus_session_tracker_t *session_tracker;
    dolus_storage_t *storage;
    dolus_intel_engine_t *intel;
    dolus_alerting_t *alerting;
    dolus_logger_t *logger;
    
    bool running;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    size_t active_sessions;
    size_t total_connections;
};

static int64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *get_client_ip(ssh_session session) {
    static char ip[INET6_ADDRSTRLEN];
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    
    int fd = ssh_get_fd(session);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        return "unknown";
    }
    
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
    } else {
        return "unknown";
    }
    
    return ip;
}

static int get_client_port(ssh_session session) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    
    int fd = ssh_get_fd(session);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        return 0;
    }
    
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        return ntohs(sin->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        return ntohs(sin6->sin6_port);
    }
    
    return 0;
}

static void emit_event(dolus_ssh_engine_t *engine, const dolus_event_t *event) {
    if (engine->event_cb) {
        engine->event_cb(event, engine->user_data);
    }
    if (engine->storage) {
        dolus_storage_write_event(engine->storage, event);
    }
}

static const char *banner_for_profile(const char *profile) {
    if (strcmp(profile, "ubuntu-20.04") == 0) return "OpenSSH_8.2p1 Ubuntu-4ubuntu0.3";
    if (strcmp(profile, "ubuntu-22.04") == 0) return "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
    if (strcmp(profile, "debian-11") == 0) return "OpenSSH_8.4p1 Debian-5+deb11u1";
    if (strcmp(profile, "debian-12") == 0) return "OpenSSH_9.2p1 Debian-2+deb12u2";
    if (strcmp(profile, "centos-7") == 0) return "OpenSSH_7.4p1, OpenSSL 1.0.2k-fips";
    if (strcmp(profile, "centos-8") == 0) return "OpenSSH_8.0p1, OpenSSL 1.1.1k";
    if (strcmp(profile, "alpine") == 0) return "OpenSSH_8.6_p1, OpenSSL 1.1.1l";
    if (strcmp(profile, "freebsd") == 0) return "OpenSSH_8.4p1, OpenSSL 1.1.1k-freebsd";
    if (strcmp(profile, "cisco") == 0) return "Cisco-1.25";
    if (strcmp(profile, "dropbear") == 0) return "SSH-2.0-dropbear_2020.81";
    return "OpenSSH_8.2p1 Ubuntu-4ubuntu0.3";
}

static void *session_worker(void *arg) {
    struct {
        dolus_ssh_engine_t *engine;
        ssh_session session;
    } *data = arg;
    
    dolus_ssh_engine_t *engine = data->engine;
    ssh_session session = data->session;
    free(data);
    
    // Increment connection counters
    pthread_mutex_lock(&engine->lock);
    engine->active_sessions++;
    engine->total_connections++;
    pthread_mutex_unlock(&engine->lock);
    
    char *session_id = NULL;
    dolus_session_t *dolus_session = NULL;
    
    dolus_source_info_t source = {0};
    source.ip = strdup(get_client_ip(session));
    source.port = get_client_port(session);
    
    // Determine address family from the actual connection
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int fd = ssh_get_fd(session);
    if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        source.family = addr.ss_family;
    } else {
        source.family = AF_INET;
    }
    
    // Use actual bind address/port from engine config (first one for now)
    const char *dst_ip = "0.0.0.0";
    int dst_port = 2222;
    if (engine->server_config.bind_address_count > 0) {
        dst_ip = engine->server_config.bind_addresses[0];
    }
    if (engine->server_config.port_count > 0) {
        dst_port = engine->server_config.ports[0];
    }
    
    dolus_session = dolus_session_create(engine->session_tracker, &source, dst_ip, dst_port);
    if (dolus_session) {
        session_id = strdup(dolus_session->session_id);
        dolus_session->start_time_ms = current_time_ms();
        
        dolus_event_t *conn_event = dolus_event_new(DOLUS_EVENT_CONNECTION_START, session_id, &source);
        dolus_connection_metadata_t conn_meta = {
            .client_version = strdup(ssh_get_client_version(session) ? ssh_get_client_version(session) : "unknown"),
            .server_version = strdup(banner_for_profile(engine->ssh_config.banner_profile)),
            .kex_algo = strdup(""),
            .host_key_algo = strdup(""),
            .cipher_c2s = strdup(""),
            .cipher_s2c = strdup(""),
            .mac_c2s = strdup(""),
            .mac_s2c = strdup(""),
            .compression_c2s = strdup("none"),
            .compression_s2c = strdup("none")
        };
        conn_event->data.connection = malloc(sizeof(dolus_connection_metadata_t));
        *conn_event->data.connection = conn_meta;
        emit_event(engine, conn_event);
        dolus_event_free(conn_event);
        
        dolus_session_add_connection_meta(dolus_session, &conn_meta);
    }
    
    if (ssh_handle_key_exchange(session)) {
        DOLUS_ERROR(engine->logger, "Key exchange failed: %s", ssh_get_error(session));
        if (dolus_session) dolus_session_end(dolus_session, "key_exchange_failed");
        ssh_free(session);
        
        pthread_mutex_lock(&engine->lock);
        engine->active_sessions--;
        pthread_mutex_unlock(&engine->lock);
        return NULL;
    }
    
    if (dolus_session && dolus_session->connection_meta) {
        dolus_session->connection_meta->kex_algo = strdup(ssh_get_kex(session));
        dolus_session->connection_meta->host_key_algo = strdup(ssh_get_hostkey_type(session) ? "rsa" : "unknown");
    }
    
    ssh_message message;
    int auth_attempt = 0;
    
    while ((message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            auth_attempt++;
            const char *username = ssh_message_auth_user(message);
            const char *password = ssh_message_auth_password(message);
            dolus_auth_method_t method = DOLUS_AUTH_METHOD_PASSWORD;
            dolus_auth_result_t result = DOLUS_AUTH_RESULT_FAILED;
            
            switch (ssh_message_subtype(message)) {
                case SSH_AUTH_METHOD_PASSWORD:
                    method = DOLUS_AUTH_METHOD_PASSWORD;
                    break;
                case SSH_AUTH_METHOD_PUBLICKEY:
                    method = DOLUS_AUTH_METHOD_PUBLICKEY;
                    break;
                case SSH_AUTH_METHOD_INTERACTIVE:
                    method = DOLUS_AUTH_METHOD_KEYBOARD_INTERACTIVE;
                    break;
                case SSH_AUTH_METHOD_GSSAPI_MIC:
                    method = DOLUS_AUTH_METHOD_GSSAPI;
                    break;
                case SSH_AUTH_METHOD_NONE:
                    method = DOLUS_AUTH_METHOD_NONE;
                    result = DOLUS_AUTH_RESULT_FAILED;
                    break;
                default:
                    method = DOLUS_AUTH_METHOD_UNKNOWN;
            }
            
            dolus_auth_metadata_t auth_meta = {
                .method = method,
                .username = strdup(username ? username : "unknown"),
                .password = NULL,
                .password_hash = NULL,
                .password_redacted = true,
                .result = result,
                .attempt_number = auth_attempt
            };
            
            if (method == DOLUS_AUTH_METHOD_PASSWORD && password) {
                switch (engine->cred_config.policy) {
                    case DOLUS_CRED_CAPTURE:
                        auth_meta.password = strdup(password);
                        auth_meta.password_redacted = false;
                        break;
                    case DOLUS_CRED_HASH: {
                        unsigned char hash[SHA256_DIGEST_LENGTH];
                        char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
                        SHA256((const unsigned char *)password, strlen(password), hash);
                        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                            snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);
                        }
                        auth_meta.password_hash = strdup(hash_hex);
                        break;
                    }
                    case DOLUS_CRED_REDACT:
                    case DOLUS_CRED_METADATA_ONLY:
                    default:
                        auth_meta.password_redacted = true;
                        break;
                }
            }
            
            if (dolus_session) {
                dolus_session_add_auth_attempt(dolus_session, &auth_meta);
            }
            
            dolus_event_t *auth_event = dolus_event_new(DOLUS_EVENT_AUTHENTICATION_ATTEMPT, session_id, &source);
            auth_event->data.auth = malloc(sizeof(dolus_auth_metadata_t));
            *auth_event->data.auth = auth_meta;
            emit_event(engine, auth_event);
            dolus_event_free(auth_event);
            
            ssh_message_reply_default(message);
        } else {
            ssh_message_reply_default(message);
        }
        
        ssh_message_free(message);
    }
    
    if (dolus_session) {
        dolus_session->end_time_ms = current_time_ms();
        dolus_session->duration_ms = dolus_session->end_time_ms - dolus_session->start_time_ms;
        dolus_session_end(dolus_session, "client_disconnect");
        
        if (engine->intel && engine->server_config.worker_threads > 0) {
            // Check if classification is enabled via intelligence config
            // For now, always classify if intel is available
            dolus_classification_metadata_t *classification = dolus_intel_classify_session(engine->intel, dolus_session);
            if (classification) {
                dolus_session_set_classification(dolus_session, classification);
                
                dolus_event_t *cls_event = dolus_event_new(DOLUS_EVENT_CLASSIFICATION, session_id, &source);
                cls_event->data.classification = classification;
                emit_event(engine, cls_event);
                dolus_event_free(cls_event);
            }
            
            dolus_intel_process_session(engine->intel, dolus_session);
            
            if (engine->alerting) {
                dolus_attacker_profile_t *profile = dolus_intel_get_attacker_profile(engine->intel, source.ip);
                dolus_alerting_check_thresholds(engine->alerting, NULL, dolus_session, profile);
            }
        }
        
        dolus_event_t *end_event = dolus_event_new(DOLUS_EVENT_CONNECTION_END, session_id, &source);
        dolus_session_metadata_t sess_meta = {
            .duration_ms = dolus_session->duration_ms,
            .auth_attempt_count = (int)dolus_session->auth_attempt_count,
            .disconnect_reason = strdup("client_disconnect")
        };
        end_event->data.session = malloc(sizeof(dolus_session_metadata_t));
        *end_event->data.session = sess_meta;
        emit_event(engine, end_event);
        dolus_event_free(end_event);
        
        if (engine->storage) {
            dolus_storage_write_session(engine->storage, dolus_session);
        }
        
        if (engine->session_cb) {
            engine->session_cb(dolus_session, engine->user_data);
        }
    }
    
    ssh_free(session);
    
    pthread_mutex_lock(&engine->lock);
    engine->active_sessions--;
    pthread_cond_signal(&engine->cond);
    pthread_mutex_unlock(&engine->lock);
    
    free(source.ip);
    free(session_id);
    return NULL;
}

static void *listener_thread(void *arg) {
    dolus_ssh_listener_t *listener = arg;
    
    while (listener->running) {
        ssh_session session = ssh_new();
        if (ssh_bind_accept(listener->bind, session) == SSH_ERROR) {
            if (!listener->running) break;
            continue;
        }
        
        struct {
            dolus_ssh_engine_t *engine;
            ssh_session session;
        } *data = malloc(sizeof(*data));
        data->engine = listener->engine;
        data->session = session;
        
        pthread_t worker;
        pthread_create(&worker, NULL, session_worker, data);
        pthread_detach(worker);
    }
    
    return NULL;
}

dolus_ssh_engine_t *dolus_ssh_engine_new(const dolus_server_config_t *server_config,
                                          const dolus_ssh_config_t *ssh_config,
                                          const dolus_credentials_config_t *cred_config) {
    dolus_ssh_engine_t *engine = calloc(1, sizeof(dolus_ssh_engine_t));
    if (!engine) return NULL;
    
    engine->server_config = *server_config;
    engine->ssh_config = *ssh_config;
    engine->cred_config = *cred_config;
    
    engine->listeners = calloc(server_config->bind_address_count * server_config->port_count,
                               sizeof(dolus_ssh_listener_t *));
    engine->session_tracker = dolus_session_tracker_new();
    
    pthread_mutex_init(&engine->lock, NULL);
    pthread_cond_init(&engine->cond, NULL);
    
    return engine;
}

void dolus_ssh_engine_free(dolus_ssh_engine_t *engine) {
    if (!engine) return;
    
    dolus_ssh_engine_stop(engine);
    
    for (size_t i = 0; i < engine->listener_count; i++) {
        if (engine->listeners[i]) {
            if (engine->listeners[i]->bind) ssh_bind_free(engine->listeners[i]->bind);
            free(engine->listeners[i]->bind_addr);
            free(engine->listeners[i]);
        }
    }
    free(engine->listeners);
    
    dolus_session_tracker_free(engine->session_tracker);
    
    pthread_mutex_destroy(&engine->lock);
    pthread_cond_destroy(&engine->cond);
    
    free(engine);
}

dolus_error_t dolus_ssh_engine_start(dolus_ssh_engine_t *engine,
                                      dolus_ssh_session_callback session_cb,
                                      dolus_ssh_event_callback event_cb,
                                      void *user_data) {
    if (!engine || engine->running) return DOLUS_ERROR_INVALID;
    
    engine->session_cb = session_cb;
    engine->event_cb = event_cb;
    engine->user_data = user_data;
    engine->running = true;
    
    for (size_t i = 0; i < engine->server_config.bind_address_count; i++) {
        for (size_t j = 0; j < engine->server_config.port_count; j++) {
            dolus_ssh_listener_t *listener = calloc(1, sizeof(dolus_ssh_listener_t));
            listener->engine = engine;
            listener->bind_addr = strdup(engine->server_config.bind_addresses[i]);
            listener->port = engine->server_config.ports[j];
            listener->bind = ssh_bind_new();
            
            ssh_bind_options_set(listener->bind, SSH_BIND_OPTIONS_BINDADDR, listener->bind_addr);
            ssh_bind_options_set(listener->bind, SSH_BIND_OPTIONS_BINDPORT, &listener->port);
            ssh_bind_options_set(listener->bind, SSH_BIND_OPTIONS_BANNER, banner_for_profile(engine->ssh_config.banner_profile));
            ssh_bind_options_set(listener->bind, SSH_BIND_OPTIONS_RSAKEY, engine->ssh_config.host_key_file);
            
            if (ssh_bind_listen(listener->bind) < 0) {
                DOLUS_ERROR(engine->logger, "Failed to listen on %s:%d: %s",
                            listener->bind_addr, listener->port, ssh_get_error(listener->bind));
                ssh_bind_free(listener->bind);
                free(listener->bind_addr);
                free(listener);
                continue;
            }
            
            listener->running = true;
            pthread_create(&listener->thread, NULL, listener_thread, listener);
            
            engine->listeners[engine->listener_count++] = listener;
        }
    }
    
    if (engine->listener_count == 0) {
        engine->running = false;
        return DOLUS_ERROR_NETWORK;
    }
    
    return DOLUS_OK;
}

dolus_error_t dolus_ssh_engine_stop(dolus_ssh_engine_t *engine) {
    if (!engine || !engine->running) return DOLUS_OK;
    
    engine->running = false;
    
    for (size_t i = 0; i < engine->listener_count; i++) {
        if (engine->listeners[i]) {
            engine->listeners[i]->running = false;
            if (engine->listeners[i]->bind) {
                ssh_bind_free(engine->listeners[i]->bind);
                engine->listeners[i]->bind = NULL;
            }
            pthread_join(engine->listeners[i]->thread, NULL);
        }
    }
    
    pthread_mutex_lock(&engine->lock);
    while (engine->active_sessions > 0) {
        pthread_cond_wait(&engine->cond, &engine->lock);
    }
    pthread_mutex_unlock(&engine->lock);
    
    return DOLUS_OK;
}

dolus_error_t dolus_ssh_engine_wait(dolus_ssh_engine_t *engine) {
    if (!engine) return DOLUS_ERROR_INVALID;
    
    for (size_t i = 0; i < engine->listener_count; i++) {
        if (engine->listeners[i]) {
            pthread_join(engine->listeners[i]->thread, NULL);
        }
    }
    
    return DOLUS_OK;
}

size_t dolus_ssh_engine_active_sessions(const dolus_ssh_engine_t *engine) {
    if (!engine) return 0;
    return engine->active_sessions;
}

size_t dolus_ssh_engine_total_connections(const dolus_ssh_engine_t *engine) {
    if (!engine) return 0;
    return engine->total_connections;
}

const char *dolus_ssh_banner_profile(const char *profile_name) {
    return banner_for_profile(profile_name);
}