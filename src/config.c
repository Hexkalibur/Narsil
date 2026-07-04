/*
 * config.c  --  IDS configuration: create defaults, load from file, free.
 *
 * Config file format (plain text, one directive per line):
 *
 *   block_ip   <ip>
 *   bad_port   <port>
 *   verbose
 *   no_network
 *   no_process
 *   no_events
 *   log        <path>
 *
 * Lines starting with '#' are comments.
 */
#include "../include/ids.h"

static void load_default_bad_ports(IdsConfig *cfg) {
    WORD defaults[] = {
        1337, 4444, 5555, 6666, 7777, 8888, 9999,  /* common RAT ports    */
        31337,                                       /* "elite" backdoor    */
        1080,                                        /* SOCKS proxy         */
        4899,                                        /* Radmin              */
        5900,                                        /* VNC (default off)   */
        6667, 6668, 6669                             /* IRC (botnet C2)     */
    };
    int n = (int)(sizeof(defaults) / sizeof(defaults[0]));
    if (n > MAX_SUSPICIOUS_PORTS) n = MAX_SUSPICIOUS_PORTS;
    memcpy(cfg->suspicious_ports, defaults, n * sizeof(WORD));
    cfg->suspicious_port_count = n;
}

IdsConfig *ids_config_create(void) {
    IdsConfig *cfg = (IdsConfig *)calloc(1, sizeof(IdsConfig));
    if (!cfg) return NULL;

    cfg->monitor_network   = TRUE;
    cfg->monitor_processes = TRUE;
    cfg->monitor_events    = TRUE;
    cfg->verbose           = FALSE;

    InitializeSRWLock(&cfg->config_lock);

    strncpy(cfg->log_path, ALERT_LOG_FILE, MAX_LOG_PATH - 1);
    load_default_bad_ports(cfg);

    return cfg;
}

BOOL ids_config_load(IdsConfig *cfg, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return FALSE;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* strip newline */
        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '#' || line[0] == '\0') continue;

        char key[64] = {0}, val[448] = {0};
        int  fields = sscanf(line, "%63s %447s", key, val);

        if (fields < 1) continue;

        if (strcmp(key, "verbose") == 0) {
            cfg->verbose = TRUE;

        } else if (strcmp(key, "no_network") == 0) {
            cfg->monitor_network = FALSE;

        } else if (strcmp(key, "no_process") == 0) {
            cfg->monitor_processes = FALSE;

        } else if (strcmp(key, "no_events") == 0) {
            cfg->monitor_events = FALSE;

        } else if (strcmp(key, "log") == 0 && fields == 2) {
            strncpy(cfg->log_path, val, MAX_LOG_PATH - 1);

        } else if (strcmp(key, "block_ip") == 0 && fields == 2) {
            if (cfg->blocked_ip_count < MAX_BLOCKED_IPS)
                strncpy(cfg->blocked_ips[cfg->blocked_ip_count++],
                        val, MAX_IP_LEN - 1);

        } else if (strcmp(key, "bad_port") == 0 && fields == 2) {
            int port = atoi(val);
            if (port > 0 && port <= 65535 &&
                cfg->suspicious_port_count < MAX_SUSPICIOUS_PORTS)
                cfg->suspicious_ports[cfg->suspicious_port_count++] =
                    (WORD)port;
        }
    }

    fclose(fp);
    return TRUE;
}

void ids_config_free(IdsConfig *cfg) {
    if (!cfg) return;
    free(cfg->rules);
    SecureZeroMemory(cfg, sizeof(IdsConfig));   /* wipe sensitive data */
    free(cfg);
}