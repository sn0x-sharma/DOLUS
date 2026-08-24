#include "cli.h"
#include "dolus.h"
#include "config.h"
#include "logging.h"
#include "../ssh/ssh_engine.h"
#include "../events/session.h"
#include "../events/event.h"
#include "../storage/storage.h"
#include "../intel/intel.h"
#include "../alerting/alerting.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

static dolus_ssh_engine_t *g_engine = NULL;
static dolus_storage_t *g_storage = NULL;
static dolus_intel_engine_t *g_intel = NULL;
static dolus_alerting_t *g_alerting = NULL;
static dolus_logger_t *g_logger = NULL;
static dolus_config_t *g_config = NULL;

static void signal_handler(int sig) {
    if (g_engine) {
        dolus_ssh_engine_stop(g_engine);
    }
}

static int cmd_start(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    g_config = dolus_config_new();
    *g_config = *config;
    
    g_logger = dolus_logger_new(&config->logging);
    
    g_storage = dolus_storage_new(&config->storage, &config->credentials);
    if (dolus_storage_init(g_storage) != DOLUS_OK) {
        DOLUS_ERROR(g_logger, "Failed to initialize storage");
        return 1;
    }
    
    g_intel = dolus_intel_new(&config->intelligence, g_storage);
    
    g_alerting = dolus_alerting_new(&config->alerting, g_storage);
    
    g_engine = dolus_ssh_engine_new(&config->server, &config->ssh, &config->credentials);
    g_engine->storage = g_storage;
    g_engine->intel = g_intel;
    g_engine->alerting = g_alerting;
    g_engine->logger = g_logger;
    
    if (dolus_ssh_engine_start(g_engine, NULL, NULL, NULL) != DOLUS_OK) {
        DOLUS_ERROR(g_logger, "Failed to start SSH engine");
        return 1;
    }
    
    DOLUS_INFO(g_logger, "DOLUS started on %d ports", config->server.port_count);
    
    dolus_ssh_engine_wait(g_engine);
    
    return 0;
}

static int cmd_stop(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (g_engine) {
        dolus_ssh_engine_stop(g_engine);
        printf("DOLUS stopped\n");
    } else {
        printf("DOLUS not running\n");
    }
    return 0;
}

static int cmd_status(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (g_engine) {
        printf("DOLUS Status: RUNNING\n");
        printf("Active sessions: %zu\n", dolus_ssh_engine_active_sessions(g_engine));
        printf("Total connections: %zu\n", dolus_ssh_engine_total_connections(g_engine));
    } else {
        printf("DOLUS Status: STOPPED\n");
    }
    return 0;
}

static int cmd_config(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts;
    dolus_config_print(config);
    return 0;
}

static int cmd_stats(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (!g_intel) {
        printf("Intelligence engine not initialized\n");
        return 1;
    }
    
    dolus_statistics_t *stats = dolus_intel_get_statistics(g_intel);
    if (!stats) {
        printf("No statistics available\n");
        return 1;
    }
    
    printf("=== DOLUS Statistics ===\n");
    printf("Total connections:     %lld\n", (long long)stats->total_connections);
    printf("Unique sources:        %lld\n", (long long)stats->unique_sources);
    printf("Total auth attempts:   %lld\n", (long long)stats->total_auth_attempts);
    printf("Failed auth attempts:  %lld\n", (long long)stats->failed_auth_attempts);
    printf("Active sessions:       %lld\n", (long long)stats->active_sessions);
    printf("\nClassifications:\n");
    for (int i = 0; i < 6; i++) {
        printf("  %s: %d\n", dolus_classification_category_string(i), stats->classification_counts[i]);
    }
    printf("\nHourly distribution:\n");
    for (int i = 0; i < 24; i++) {
        if (stats->hourly_counts[i] > 0) {
            printf("  %02d:00 - %d\n", i, stats->hourly_counts[i]);
        }
    }
    
    dolus_statistics_free(stats);
    return 0;
}

static int cmd_sessions(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (!g_engine) {
        printf("Engine not running\n");
        return 1;
    }
    
    size_t count = 0;
    dolus_session_t **sessions = dolus_session_list(g_engine->session_tracker, &count);
    
    printf("=== Sessions (%zu total) ===\n", count);
    for (size_t i = 0; i < count && (opts->limit <= 0 || i < (size_t)opts->limit); i++) {
        dolus_session_t *s = sessions[i];
        printf("  %s | %s:%d | %lldms | %zu auth | %s\n",
               s->session_id, s->source.ip, s->source.port,
               (long long)s->duration_ms, s->auth_attempt_count,
               s->active ? "active" : "ended");
    }
    
    free(sessions);
    return 0;
}

static int cmd_attackers(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)config;
    
    if (!g_intel) {
        printf("Intelligence engine not initialized\n");
        return 1;
    }
    
    size_t count = 0;
    dolus_attacker_profile_t **attackers = dolus_intel_list_attackers(g_intel, &count, opts->limit > 0 ? opts->limit : 20);
    
    printf("=== Top Attackers (%zu total) ===\n", count);
    for (size_t i = 0; i < count; i++) {
        dolus_attacker_profile_t *a = attackers[i];
        printf("  %s | sessions: %d | auth: %d | users: %d | ", 
               a->ip, a->session_count, a->auth_attempt_count, a->unique_usernames);
        for (int j = 0; j < 6; j++) {
            if (a->classifications[j] > 0) {
                printf("%s:%d ", dolus_classification_category_string(j), a->classifications[j]);
            }
        }
        printf("\n");
    }
    
    free(attackers);
    return 0;
}

static int cmd_scanners(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (!g_intel) {
        printf("Intelligence engine not initialized\n");
        return 1;
    }
    
    size_t count = 0;
    dolus_attacker_profile_t **attackers = dolus_intel_list_attackers(g_intel, &count, 100);
    
    printf("=== Scanners ===\n");
    for (size_t i = 0; i < count; i++) {
        dolus_attacker_profile_t *a = attackers[i];
        if (a->classifications[DOLUS_CLASS_SCANNER] > 0 || a->auth_attempt_count == 0) {
            printf("  %s | sessions: %d | auth: %d\n", a->ip, a->session_count, a->auth_attempt_count);
        }
    }
    
    free(attackers);
    return 0;
}

static int cmd_events(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("Event query not yet implemented\n");
    return 0;
}

static int cmd_database(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("Database management not yet implemented\n");
    return 0;
}

static int cmd_version(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("DOLUS %s by %s\n", dolus_version(), dolus_author());
    return 0;
}

static int cmd_session_show(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)config;
    
    if (!g_engine || !opts->session_id) {
        printf("Session ID required\n");
        return 1;
    }
    
    dolus_session_t *session = dolus_session_get(g_engine->session_tracker, opts->session_id);
    if (!session) {
        printf("Session not found\n");
        return 1;
    }
    
    printf("=== Session %s ===\n", session->session_id);
    printf("Source: %s:%d\n", session->source.ip, session->source.port);
    printf("Destination: %s:%d\n", session->dst_ip, session->dst_port);
    printf("Start: %lld\n", (long long)session->start_time_ms);
    printf("End: %lld\n", (long long)session->end_time_ms);
    printf("Duration: %lld ms\n", (long long)session->duration_ms);
    printf("Auth attempts: %zu\n", session->auth_attempt_count);
    printf("Active: %s\n", session->active ? "yes" : "no");
    printf("Disconnect reason: %s\n", session->disconnect_reason ? session->disconnect_reason : "unknown");
    
    if (session->connection_meta) {
        printf("Client version: %s\n", session->connection_meta->client_version);
        printf("KEX: %s\n", session->connection_meta->kex_algo);
    }
    
    for (size_t i = 0; i < session->auth_attempt_count; i++) {
        dolus_auth_metadata_t *a = session->auth_attempts[i];
        printf("  Auth %zu: %s | %s | %s\n", i + 1,
               dolus_auth_method_string(a->method),
               a->username,
               dolus_auth_result_string(a->result));
    }
    
    if (session->classification) {
        printf("Classification: %s (%.2f%%)\n",
               dolus_classification_category_string(session->classification->category),
               session->classification->confidence * 100);
    }
    
    return 0;
}

static int cmd_session_replay(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("Session replay not yet implemented\n");
    return 0;
}

static int cmd_timeline(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("Timeline not yet implemented\n");
    return 0;
}

static int cmd_campaigns(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    
    if (!g_intel) {
        printf("Intelligence engine not initialized\n");
        return 1;
    }
    
    size_t count = 0;
    dolus_campaign_t **campaigns = dolus_intel_get_campaigns(g_intel, &count);
    
    printf("=== Campaigns (%zu total) ===\n", count);
    for (size_t i = 0; i < count; i++) {
        dolus_campaign_t *c = campaigns[i];
        printf("  %s | sources: %zu | sessions: %d | confidence: %.2f\n",
               c->campaign_id, c->source_count, c->session_count, c->confidence);
    }
    
    free(campaigns);
    return 0;
}

static int cmd_fingerprints(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    (void)opts; (void)config;
    printf("Fingerprints not yet implemented\n");
    return 0;
}

static int (*cmd_handlers[])(const dolus_cli_options_t *, const dolus_config_t *) = {
    [DOLUS_CMD_START] = cmd_start,
    [DOLUS_CMD_STOP] = cmd_stop,
    [DOLUS_CMD_STATUS] = cmd_status,
    [DOLUS_CMD_CONFIG] = cmd_config,
    [DOLUS_CMD_STATS] = cmd_stats,
    [DOLUS_CMD_SESSIONS] = cmd_sessions,
    [DOLUS_CMD_ATTACKERS] = cmd_attackers,
    [DOLUS_CMD_SCANNERS] = cmd_scanners,
    [DOLUS_CMD_EVENTS] = cmd_events,
    [DOLUS_CMD_DATABASE] = cmd_database,
    [DOLUS_CMD_VERSION] = cmd_version,
    [DOLUS_CMD_SESSION_SHOW] = cmd_session_show,
    [DOLUS_CMD_SESSION_REPLAY] = cmd_session_replay,
    [DOLUS_CMD_TIMELINE] = cmd_timeline,
    [DOLUS_CMD_CAMPAIGNS] = cmd_campaigns,
    [DOLUS_CMD_FINGERPRINTS] = cmd_fingerprints,
};

dolus_error_t dolus_cli_parse(int argc, char **argv, dolus_cli_options_t *opts,
                               dolus_config_t *config) {
    memset(opts, 0, sizeof(dolus_cli_options_t));
    opts->command = DOLUS_CMD_HELP;
    opts->limit = -1;
    
    static struct option long_opts[] = {
        {"port", required_argument, 0, 'p'},
        {"bind", required_argument, 0, 'b'},
        {"log-file", required_argument, 0, 'l'},
        {"host-key", required_argument, 0, 'r'},
        {"pid-file", required_argument, 0, 'f'},
        {"daemon", no_argument, 0, 'd'},
        {"config", required_argument, 0, 'c'},
        {"log-format", required_argument, 0, 'F'},
        {"verbose", no_argument, 0, 'v'},
        {"json", no_argument, 0, 'j'},
        {"session", required_argument, 0, 's'},
        {"ip", required_argument, 0, 'i'},
        {"limit", required_argument, 0, 'n'},
        {"since", required_argument, 0, 'S'},
        {"until", required_argument, 0, 'U'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:l:r:f:dc:F:vjs:i:n:S:U:o:hV", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': dolus_config_parse_int(optarg, &config->server.ports[0]); break;
            case 'b': {
                dolus_config_free_string_array(config->server.bind_addresses, config->server.bind_address_count);
                config->server.bind_addresses = calloc(1, sizeof(char *));
                config->server.bind_addresses[0] = strdup(optarg);
                config->server.bind_address_count = 1;
                break;
            }
            case 'l': free(config->logging.file_path); config->logging.file_path = strdup(optarg); break;
            case 'r': free(config->ssh.host_key_file); config->ssh.host_key_file = strdup(optarg); break;
            case 'f': free(config->pid_file); config->pid_file = strdup(optarg); break;
            case 'd': config->daemonize = true; break;
            case 'c': config->config_file = strdup(optarg); break;
            case 'F': if (strcmp(optarg, "json") == 0) config->logging.format = DOLUS_LOG_FORMAT_JSON; break;
            case 'v': opts->verbose++; break;
            case 'j': opts->json_output = true; break;
            case 's': opts->session_id = strdup(optarg); break;
            case 'i': opts->ip_address = strdup(optarg); break;
            case 'n': dolus_config_parse_int(optarg, &opts->limit); break;
            case 'S': opts->since = strdup(optarg); break;
            case 'U': opts->until = strdup(optarg); break;
            case 'o': opts->output_format = strdup(optarg); break;
            case 'h': opts->command = DOLUS_CMD_HELP; break;
            case 'V': opts->command = DOLUS_CMD_VERSION; break;
        }
    }
    
    if (optind < argc) {
        const char *cmd = argv[optind];
        if (strcmp(cmd, "start") == 0) opts->command = DOLUS_CMD_START;
        else if (strcmp(cmd, "stop") == 0) opts->command = DOLUS_CMD_STOP;
        else if (strcmp(cmd, "status") == 0) opts->command = DOLUS_CMD_STATUS;
        else if (strcmp(cmd, "config") == 0) opts->command = DOLUS_CMD_CONFIG;
        else if (strcmp(cmd, "stats") == 0) opts->command = DOLUS_CMD_STATS;
        else if (strcmp(cmd, "sessions") == 0) opts->command = DOLUS_CMD_SESSIONS;
        else if (strcmp(cmd, "attackers") == 0) opts->command = DOLUS_CMD_ATTACKERS;
        else if (strcmp(cmd, "scanners") == 0) opts->command = DOLUS_CMD_SCANNERS;
        else if (strcmp(cmd, "events") == 0) opts->command = DOLUS_CMD_EVENTS;
        else if (strcmp(cmd, "database") == 0) opts->command = DOLUS_CMD_DATABASE;
        else if (strcmp(cmd, "session") == 0) {
            if (optind + 1 < argc) {
                const char *sub = argv[++optind];
                if (strcmp(sub, "show") == 0) opts->command = DOLUS_CMD_SESSION_SHOW;
                else if (strcmp(sub, "replay") == 0) opts->command = DOLUS_CMD_SESSION_REPLAY;
            }
        } else if (strcmp(cmd, "timeline") == 0) opts->command = DOLUS_CMD_TIMELINE;
        else if (strcmp(cmd, "campaigns") == 0) opts->command = DOLUS_CMD_CAMPAIGNS;
        else if (strcmp(cmd, "fingerprints") == 0) opts->command = DOLUS_CMD_FINGERPRINTS;
    }
    
    return DOLUS_OK;
}

int dolus_cli_run(const dolus_cli_options_t *opts, const dolus_config_t *config) {
    if (opts->command >= DOLUS_CMD_START && opts->command <= DOLUS_CMD_FINGERPRINTS) {
        if (cmd_handlers[opts->command]) {
            return cmd_handlers[opts->command](opts, config);
        }
    }
    
    dolus_cli_print_help("dolus");
    return 1;
}

void dolus_cli_print_help(const char *progname) {
    printf("DOLUS %s - SSH Deception & Attack Intelligence Platform\n\n", dolus_version());
    printf("Usage: %s [global options] <command> [command options]\n\n", progname);
    printf("Global Options:\n");
    printf("  -c, --config FILE       Configuration file\n");
    printf("  -p, --port PORT         Listen port (default: 2222)\n");
    printf("  -b, --bind ADDRESS      Bind address (default: 0.0.0.0)\n");
    printf("  -l, --log-file FILE     Log file path\n");
    printf("  -r, --host-key FILE     RSA host key file\n");
    printf("  -f, --pid-file FILE     PID file path\n");
    printf("  -d, --daemon            Run as daemon\n");
    printf("  -F, --log-format FMT    Log format: text|json (default: text)\n");
    printf("  -v, --verbose           Increase verbosity\n");
    printf("  -j, --json              JSON output for commands\n");
    printf("  -h, --help              Show this help\n");
    printf("  -V, --version           Show version\n\n");
    printf("Commands:\n");
    printf("  start                   Start the honeypot\n");
    printf("  stop                    Stop the honeypot\n");
    printf("  status                  Show status\n");
    printf("  config                  Show current configuration\n");
    printf("  stats                   Show statistics\n");
    printf("  sessions [--limit N]    List sessions\n");
    printf("  attackers [--limit N]   List top attackers\n");
    printf("  scanners                List detected scanners\n");
    printf("  events                  Query events\n");
    printf("  database                Database management\n");
    printf("  session show <id>       Show session details\n");
    printf("  session replay <id>     Replay session\n");
    printf("  timeline                Show attack timeline\n");
    printf("  campaigns               Show correlated campaigns\n");
    printf("  fingerprints            Show SSH fingerprints\n");
}

void dolus_cli_print_version(void) {
    printf("DOLUS %s by %s\n", dolus_version(), dolus_author());
}

const char *dolus_command_string(dolus_command_t cmd) {
    static const char *strings[] = {
        "start", "stop", "status", "config", "stats", "sessions",
        "attackers", "scanners", "events", "database", "version", "help",
        "session_show", "session_replay", "timeline", "campaigns", "fingerprints"
    };
    if (cmd >= 0 && cmd <= DOLUS_CMD_FINGERPRINTS) return strings[cmd];
    return "unknown";
}