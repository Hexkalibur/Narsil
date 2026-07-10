/*
 * config.c  --  Narsil configuration: create defaults, load from file, free.
 *
 * Config file format (plain text, one directive per line):
 *
 *   log_path        <path>       alert JSONL log destination
 *   blocked_ip      <ip[/cidr]>  flag any connection to/from this IP or block
 *   suspicious_port <port>       flag any endpoint on this port
 *   verbose                      enable debug output
 *
 *   # Module toggles: skip a scan module entirely
 *   no_kernel
 *   no_rootkit
 *   no_persistence
 *   no_process
 *   no_memory
 *   no_network
 *   no_events
 *
 *   # v0.2 -- noise control
 *   allow_rwx        <exe name>  don't alert plain RWX findings in this proc
 *   suppress         <substring> drop any alert whose description matches
 *   known_udp_port   <port>      extra port not flagged as unknown service
 *   known_tcp_port   <port>      extra port not flagged as unknown service
 *   memory_strict                restore v0.1 behavior: one HIGH per RWX region
 *   events_hours     <n>          event-log lookback window (default 24)
 *
 * Lines starting with '#' are comments. Legacy directive aliases
 * (log, block_ip, bad_port) are still accepted for compatibility.
 */
#include "../include/ids.h"

/* Parse "a.b.c.d/nn" into network/mask (host byte order not required --
   we keep everything in the same byte order as struct in_addr.s_addr and
   compare with a matching mask, so endianness cancels out). */
static BOOL parse_cidr(const char *spec, DWORD *net, DWORD *mask) {
    char buf[64];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return FALSE;
    }

    unsigned a, b, c, d;
    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return FALSE;
    if (a > 255 || b > 255 || c > 255 || d > 255) return FALSE;

    DWORD host_order = (a << 24) | (b << 16) | (c << 8) | d;
    DWORD mask_host  = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));

    /* Convert to network byte order to match struct in_addr.s_addr, which
       is how narsil_ip_blocked() receives addresses from getsockopt/ip_str. */
    *net  = htonl(host_order & mask_host);
    *mask = htonl(mask_host);
    return TRUE;
}

IdsConfig *g_active_cfg = NULL;

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

    cfg->verbose = FALSE;

    /* Every scan module runs unless explicitly disabled. */
    cfg->scan_kernel      = TRUE;
    cfg->scan_rootkit     = TRUE;
    cfg->scan_persistence = TRUE;
    cfg->scan_processes   = TRUE;
    cfg->scan_memory      = TRUE;
    cfg->scan_network     = TRUE;
    cfg->scan_events      = TRUE;

    InitializeSRWLock(&cfg->config_lock);

    cfg->memory_strict      = FALSE;
    cfg->events_hours_back  = 24;

    strncpy(cfg->log_path, ALERT_LOG_FILE, MAX_LOG_PATH - 1);
    load_default_bad_ports(cfg);

    g_active_cfg = cfg;
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

        } else if (strcmp(key, "no_kernel") == 0) {
            cfg->scan_kernel = FALSE;
        } else if (strcmp(key, "no_rootkit") == 0) {
            cfg->scan_rootkit = FALSE;
        } else if (strcmp(key, "no_persistence") == 0) {
            cfg->scan_persistence = FALSE;
        } else if (strcmp(key, "no_process") == 0) {
            cfg->scan_processes = FALSE;
        } else if (strcmp(key, "no_memory") == 0) {
            cfg->scan_memory = FALSE;
        } else if (strcmp(key, "no_network") == 0) {
            cfg->scan_network = FALSE;
        } else if (strcmp(key, "no_events") == 0) {
            cfg->scan_events = FALSE;

        } else if ((strcmp(key, "log_path") == 0 || strcmp(key, "log") == 0)
                   && fields == 2) {
            strncpy(cfg->log_path, val, MAX_LOG_PATH - 1);
            cfg->log_path[MAX_LOG_PATH - 1] = '\0';

        } else if ((strcmp(key, "blocked_ip") == 0 || strcmp(key, "block_ip") == 0)
                   && fields == 2) {
            if (strchr(val, '/')) {
                DWORD net, mask;
                if (cfg->blocked_net_count < MAX_BLOCKED_IPS && parse_cidr(val, &net, &mask)) {
                    cfg->blocked_nets[cfg->blocked_net_count].net  = net;
                    cfg->blocked_nets[cfg->blocked_net_count].mask = mask;
                    cfg->blocked_net_count++;
                } else {
                    LOG_WARN("config: invalid CIDR block '%s' ignored", val);
                }
            } else if (cfg->blocked_ip_count < MAX_BLOCKED_IPS) {
                strncpy(cfg->blocked_ips[cfg->blocked_ip_count], val, MAX_IP_LEN - 1);
                cfg->blocked_ips[cfg->blocked_ip_count][MAX_IP_LEN - 1] = '\0';
                cfg->blocked_ip_count++;
            } else {
                LOG_WARN("config: blocked IP list full (%d), ignoring %s",
                         MAX_BLOCKED_IPS, val);
            }

        } else if ((strcmp(key, "suspicious_port") == 0 || strcmp(key, "bad_port") == 0)
                   && fields == 2) {
            int port = atoi(val);
            if (port <= 0 || port > 65535) {
                LOG_WARN("config: invalid port '%s' ignored", val);
            } else if (cfg->suspicious_port_count < MAX_SUSPICIOUS_PORTS) {
                cfg->suspicious_ports[cfg->suspicious_port_count++] = (WORD)port;
            } else {
                LOG_WARN("config: suspicious port list full (%d), ignoring %d",
                         MAX_SUSPICIOUS_PORTS, port);
            }

        } else if (strcmp(key, "allow_rwx") == 0 && fields == 2) {
            if (cfg->allow_rwx_count < MAX_ALLOW_PROCS) {
                strncpy(cfg->allow_rwx[cfg->allow_rwx_count], val,
                        sizeof(cfg->allow_rwx[0]) - 1);
                cfg->allow_rwx_count++;
            } else {
                LOG_WARN("config: allow_rwx list full (%d), ignoring %s",
                         MAX_ALLOW_PROCS, val);
            }

        } else if (strcmp(key, "suppress") == 0 && fields == 2) {
            if (cfg->suppress_count < MAX_SUPPRESS) {
                strncpy(cfg->suppress[cfg->suppress_count], val,
                        sizeof(cfg->suppress[0]) - 1);
                cfg->suppress_count++;
            } else {
                LOG_WARN("config: suppress list full (%d), ignoring %s",
                         MAX_SUPPRESS, val);
            }

        } else if (strcmp(key, "known_udp_port") == 0 && fields == 2) {
            int port = atoi(val);
            if (port <= 0 || port > 65535) {
                LOG_WARN("config: invalid port '%s' ignored", val);
            } else if (cfg->known_udp_port_count < MAX_KNOWN_PORTS) {
                cfg->known_udp_ports[cfg->known_udp_port_count++] = (WORD)port;
            }

        } else if (strcmp(key, "known_tcp_port") == 0 && fields == 2) {
            int port = atoi(val);
            if (port <= 0 || port > 65535) {
                LOG_WARN("config: invalid port '%s' ignored", val);
            } else if (cfg->known_tcp_port_count < MAX_KNOWN_PORTS) {
                cfg->known_tcp_ports[cfg->known_tcp_port_count++] = (WORD)port;
            }

        } else if (strcmp(key, "memory_strict") == 0) {
            cfg->memory_strict = TRUE;

        } else if (strcmp(key, "events_hours") == 0 && fields == 2) {
            int hours = atoi(val);
            cfg->events_hours_back = (hours > 0) ? hours : 24;

        } else {
            LOG_WARN("config: unknown directive '%s' ignored", key);
        }
    }

    fclose(fp);
    return TRUE;
}

void ids_config_free(IdsConfig *cfg) {
    if (!cfg) return;
    if (g_active_cfg == cfg) g_active_cfg = NULL;
    SecureZeroMemory(cfg, sizeof(IdsConfig));   /* wipe sensitive data */
    free(cfg);
}
