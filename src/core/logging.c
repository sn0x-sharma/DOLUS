#include "logging.h"
#include "dolus.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

struct dolus_logger {
    dolus_logging_config_t config;
    FILE *file_handle;
    pthread_mutex_t mutex;
    size_t current_size;
    char *file_path;
};

static const char *level_strings[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

static int64_t current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *format_timestamp(int64_t ms, char *buf, size_t len) {
    time_t sec = ms / 1000;
    struct tm tm;
    gmtime_r(&sec, &tm);
    int msec = ms % 1000;
    snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, msec);
    return buf;
}

static dolus_error_t open_log_file(dolus_logger_t *logger) {
    if (logger->file_handle) return DOLUS_OK;
    
    logger->file_handle = fopen(logger->file_path, "a");
    if (!logger->file_handle) return DOLUS_ERROR_IO;
    
    struct stat st;
    if (stat(logger->file_path, &st) == 0) {
        logger->current_size = st.st_size;
    }
    
    return DOLUS_OK;
}

static void close_log_file(dolus_logger_t *logger) {
    if (logger->file_handle) {
        fclose(logger->file_handle);
        logger->file_handle = NULL;
    }
}

static dolus_error_t rotate_log_file(dolus_logger_t *logger) {
    close_log_file(logger);
    
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char rotated[1024];
    snprintf(rotated, sizeof(rotated), "%s.%04d%02d%02d-%02d%02d%02d",
             logger->file_path,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    
    rename(logger->file_path, rotated);
    
    logger->current_size = 0;
    return open_log_file(logger);
}

static void write_text_log(dolus_logger_t *logger, dolus_log_level_t level,
                           const char *timestamp, const char *message) {
    fprintf(logger->file_handle, "[%s] [%s] %s\n", timestamp, level_strings[level], message);
    logger->current_size += strlen(timestamp) + strlen(level_strings[level]) + strlen(message) + 10;
}

static void write_json_log(dolus_logger_t *logger, dolus_log_level_t level,
                           const char *timestamp, const char *message,
                           const char *file, int line, const char *func) {
    fprintf(logger->file_handle,
            "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\",\"file\":\"%s\",\"line\":%d,\"function\":\"%s\"}\n",
            timestamp, level_strings[level], message, file, line, func);
    logger->current_size += 200 + strlen(message);
}

dolus_logger_t *dolus_logger_new(const dolus_logging_config_t *config) {
    dolus_logger_t *logger = calloc(1, sizeof(dolus_logger_t));
    if (!logger) return NULL;
    
    logger->config = *config;
    logger->file_path = strdup(config->file_path);
    if (!logger->file_path) {
        free(logger);
        return NULL;
    }
    
    pthread_mutex_init(&logger->mutex, NULL);
    
    if (config->format == DOLUS_LOG_FORMAT_TEXT || config->format == DOLUS_LOG_FORMAT_JSON) {
        for (size_t i = 0; i < config->output_count; i++) {
            if (strcmp(config->outputs[i], "file") == 0) {
                open_log_file(logger);
                break;
            }
        }
    }
    
    return logger;
}

void dolus_logger_free(dolus_logger_t *logger) {
    if (!logger) return;
    
    close_log_file(logger);
    free(logger->file_path);
    pthread_mutex_destroy(&logger->mutex);
    free(logger);
}

void dolus_logger_log(dolus_logger_t *logger, dolus_log_level_t level,
                      const char *file, int line, const char *func,
                      const char *fmt, ...) {
    if (!logger || level < logger->config.level) return;
    
    char message[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    char timestamp[32];
    format_timestamp(current_time_ms(), timestamp, sizeof(timestamp));
    
    pthread_mutex_lock(&logger->mutex);
    
    if (logger->config.format == DOLUS_LOG_FORMAT_TEXT) {
        if (logger->config.output_count > 0) {
            for (size_t i = 0; i < logger->config.output_count; i++) {
                if (strcmp(logger->config.outputs[i], "file") == 0) {
                    if (logger->file_handle) {
                        write_text_log(logger, level, timestamp, message);
                        if (logger->current_size > logger->config.max_size_mb * 1024 * 1024) {
                            rotate_log_file(logger);
                        }
                    }
                } else if (strcmp(logger->config.outputs[i], "stdout") == 0 && logger->config.console_output) {
                    printf("[%s] [%s] %s\n", timestamp, level_strings[level], message);
                }
            }
        }
    } else {
        for (size_t i = 0; i < logger->config.output_count; i++) {
            if (strcmp(logger->config.outputs[i], "file") == 0) {
                if (logger->file_handle) {
                    write_json_log(logger, level, timestamp, message, file, line, func);
                    if (logger->current_size > logger->config.max_size_mb * 1024 * 1024) {
                        rotate_log_file(logger);
                    }
                }
            } else if (strcmp(logger->config.outputs[i], "stdout") == 0 && logger->config.console_output) {
                char json[4300];
                snprintf(json, sizeof(json),
                         "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\",\"file\":\"%s\",\"line\":%d,\"function\":\"%s\"}",
                         timestamp, level_strings[level], message, file, line, func);
                printf("%s\n", json);
            }
        }
    }
    
    pthread_mutex_unlock(&logger->mutex);
}

void dolus_logger_log_event(dolus_logger_t *logger, const dolus_event_t *event) {
    if (!logger || !event) return;
    
    char *json = dolus_event_to_json(event);
    if (!json) return;
    
    pthread_mutex_lock(&logger->mutex);
    
    for (size_t i = 0; i < logger->config.output_count; i++) {
        if (strcmp(logger->config.outputs[i], "file") == 0 && logger->file_handle) {
            fprintf(logger->file_handle, "%s\n", json);
            logger->current_size += strlen(json) + 1;
            if (logger->current_size > logger->config.max_size_mb * 1024 * 1024) {
                rotate_log_file(logger);
            }
        } else if (strcmp(logger->config.outputs[i], "stdout") == 0 && logger->config.console_output) {
            printf("%s\n", json);
        }
    }
    
    pthread_mutex_unlock(&logger->mutex);
    free(json);
}

dolus_error_t dolus_logger_rotate(dolus_logger_t *logger) {
    if (!logger) return DOLUS_ERROR_INVALID;
    
    pthread_mutex_lock(&logger->mutex);
    dolus_error_t err = rotate_log_file(logger);
    pthread_mutex_unlock(&logger->mutex);
    
    return err;
}