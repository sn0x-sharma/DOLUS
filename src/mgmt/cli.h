#ifndef DOLUS_CLI_H
#define DOLUS_CLI_H

#include "../core/dolus.h"
#include "../core/config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DOLUS_CMD_START = 0,
    DOLUS_CMD_STOP = 1,
    DOLUS_CMD_STATUS = 2,
    DOLUS_CMD_CONFIG = 3,
    DOLUS_CMD_STATS = 4,
    DOLUS_CMD_SESSIONS = 5,
    DOLUS_CMD_ATTACKERS = 6,
    DOLUS_CMD_SCANNERS = 7,
    DOLUS_CMD_EVENTS = 8,
    DOLUS_CMD_DATABASE = 9,
    DOLUS_CMD_VERSION = 10,
    DOLUS_CMD_HELP = 11,
    DOLUS_CMD_SESSION_SHOW = 12,
    DOLUS_CMD_SESSION_REPLAY = 13,
    DOLUS_CMD_TIMELINE = 14,
    DOLUS_CMD_CAMPAIGNS = 15,
    DOLUS_CMD_FINGERPRINTS = 16
} dolus_command_t;

typedef struct dolus_cli_options {
    dolus_command_t command;
    char *config_file;
    bool daemonize;
    int verbose;
    bool json_output;
    char *session_id;
    char *ip_address;
    int limit;
    char *since;
    char *until;
    char *output_format;
} dolus_cli_options_t;

dolus_error_t dolus_cli_parse(int argc, char **argv, dolus_cli_options_t *opts,
                               dolus_config_t *config);

int dolus_cli_run(const dolus_cli_options_t *opts, const dolus_config_t *config);

void dolus_cli_print_help(const char *progname);
void dolus_cli_print_version(void);

const char *dolus_command_string(dolus_command_t cmd);

#ifdef __cplusplus
}
#endif

#endif