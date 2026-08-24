#ifndef DOLUS_LOGGING_H
#define DOLUS_LOGGING_H

#include "dolus.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dolus_logger dolus_logger_t;

dolus_logger_t *dolus_logger_new(const dolus_logging_config_t *config);
void dolus_logger_free(dolus_logger_t *logger);

void dolus_logger_log(dolus_logger_t *logger, dolus_log_level_t level,
                      const char *file, int line, const char *func,
                      const char *fmt, ...);

void dolus_logger_log_event(dolus_logger_t *logger, const dolus_event_t *event);

dolus_error_t dolus_logger_rotate(dolus_logger_t *logger);

#define DOLUS_LOG(logger, level, fmt, ...) \
    dolus_logger_log(logger, level, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define DOLUS_DEBUG(logger, fmt, ...) DOLUS_LOG(logger, DOLUS_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define DOLUS_INFO(logger, fmt, ...) DOLUS_LOG(logger, DOLUS_LOG_INFO, fmt, ##__VA_ARGS__)
#define DOLUS_WARN(logger, fmt, ...) DOLUS_LOG(logger, DOLUS_LOG_WARN, fmt, ##__VA_ARGS__)
#define DOLUS_ERROR(logger, fmt, ...) DOLUS_LOG(logger, DOLUS_LOG_ERROR, fmt, ##__VA_ARGS__)
#define DOLUS_FATAL(logger, fmt, ...) DOLUS_LOG(logger, DOLUS_LOG_FATAL, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif