#include "dolus.h"
#include "config.h"
#include "cli.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    dolus_config_t *config = dolus_config_new();
    if (!config) {
        fprintf(stderr, "Failed to create configuration\n");
        return 1;
    }
    
    dolus_config_load_defaults(config);
    
    if (config->config_file) {
        dolus_config_load(config, config->config_file);
    } else {
        const char *default_paths[] = {
            "/etc/dolus/dolus.conf",
            "./dolus.conf",
            "dolus.conf",
            NULL
        };
        for (int i = 0; default_paths[i]; i++) {
            if (dolus_config_load(config, default_paths[i]) == DOLUS_OK) {
                break;
            }
        }
    }
    
    dolus_config_apply_env(config);
    
    dolus_cli_options_t opts;
    dolus_cli_parse(argc, argv, &opts, config);
    
    if (dolus_config_validate(config) != DOLUS_OK) {
        fprintf(stderr, "Invalid configuration\n");
        dolus_config_free(config);
        return 1;
    }
    
    int ret = dolus_cli_run(&opts, config);
    
    if (opts.session_id) free(opts.session_id);
    if (opts.ip_address) free(opts.ip_address);
    if (opts.since) free(opts.since);
    if (opts.until) free(opts.until);
    if (opts.output_format) free(opts.output_format);
    
    dolus_config_free(config);
    return ret;
}