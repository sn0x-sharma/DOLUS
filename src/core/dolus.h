#ifndef DOLUS_H
#define DOLUS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOLUS_VERSION "1.0.0"
#define DOLUS_AUTHOR "DOLUS Contributors"

typedef enum {
    DOLUS_OK = 0,
    DOLUS_ERROR = -1,
    DOLUS_ERROR_NOMEM = -2,
    DOLUS_ERROR_INVALID = -3,
    DOLUS_ERROR_NOTFOUND = -4,
    DOLUS_ERROR_BUSY = -5,
    DOLUS_ERROR_TIMEOUT = -6,
    DOLUS_ERROR_PERM = -7,
    DOLUS_ERROR_IO = -8,
    DOLUS_ERROR_CONFIG = -9,
    DOLUS_ERROR_NETWORK = -10,
    DOLUS_ERROR_DB = -11,
    DOLUS_ERROR_CRYPTO = -12
} dolus_error_t;

typedef enum {
    DOLUS_LOG_DEBUG = 0,
    DOLUS_LOG_INFO = 1,
    DOLUS_LOG_WARN = 2,
    DOLUS_LOG_ERROR = 3,
    DOLUS_LOG_FATAL = 4
} dolus_log_level_t;

typedef enum {
    DOLUS_LOG_FORMAT_TEXT = 0,
    DOLUS_LOG_FORMAT_JSON = 1
} dolus_log_format_t;

typedef struct dolus_config dolus_config_t;
typedef struct dolus_context dolus_context_t;
typedef struct dolus_session dolus_session_t;
typedef struct dolus_event dolus_event_t;

const char *dolus_error_string(dolus_error_t err);
const char *dolus_version(void);
const char *dolus_author(void);

#ifdef __cplusplus
}
#endif

#endif