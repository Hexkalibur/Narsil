/*
 * alert.c -- Alert dispatch: console output, JSONL file logging.
 *
 * json_escape is exported as narsil_json_escape() so report.c
 * can use it without duplicating the implementation.
 */
#include "../include/ids.h"

/* Global verbose flag — defined in main.c, set via -v */
extern BOOL g_verbose;

/* Console colors (Windows only) */
#define CON_RED    (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define CON_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CON_CYAN   (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define CON_WHITE  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

static HANDLE g_con = NULL;
static void con_color(WORD c) {
    if (!g_con) g_con = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(g_con, c);
}

/* -----------------------------------------------
   String helpers
   ----------------------------------------------- */
const char *ids_severity_str(Severity s) {
    switch (s) {
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

const char *ids_alert_type_str(AlertType t) {
    switch (t) {
        case ALERT_PORT_SCAN:          return "PORT_SCAN";
        case ALERT_BLOCKED_IP:         return "BLOCKED_IP";
        case ALERT_ANOMALOUS_TRAFFIC:  return "ANOMALOUS_TRAFFIC";
        case ALERT_UNKNOWN_SERVICE:    return "UNKNOWN_SERVICE";
        case ALERT_C2_BEACON:          return "C2_BEACON";
        case ALERT_SUSPICIOUS_PROCESS: return "SUSPICIOUS_PROCESS";
        case ALERT_BRUTE_FORCE:        return "BRUTE_FORCE";
        case ALERT_SUSPICIOUS_EVENT:   return "SUSPICIOUS_EVENT";
        case ALERT_DEFENDER_EVENT:     return "DEFENDER_EVENT";
        case ALERT_LOLBIN:             return "LOLBIN";
        case ALERT_CREDENTIAL_ACCESS:  return "CREDENTIAL_ACCESS";
        case ALERT_SUSPICIOUS_CMDLINE: return "SUSPICIOUS_CMDLINE";
        case ALERT_SUSPICIOUS_DRIVER:  return "SUSPICIOUS_DRIVER";
        case ALERT_HIDDEN_PROCESS:     return "HIDDEN_PROCESS";
        case ALERT_PERSISTENCE:        return "PERSISTENCE";
        case ALERT_MEMORY_ANOMALY:     return "MEMORY_ANOMALY";
        case ALERT_INJECTED_PE:        return "INJECTED_PE";
        case ALERT_INJECTED_THREAD:    return "INJECTED_THREAD";
        case ALERT_YARA_MATCH:         return "YARA_MATCH";
        case ALERT_FIM:                return "FIM";
        case ALERT_SENSITIVE_DATA:     return "SENSITIVE_DATA";
        case ALERT_PLATFORM_INTEGRITY: return "PLATFORM_INTEGRITY";
        case ALERT_KEYLOGGER:          return "KEYLOGGER";
        case ALERT_CLIPBOARD:          return "CLIPBOARD";
        case ALERT_SCREEN_CAPTURE:     return "SCREEN_CAPTURE";
        case ALERT_ANTIFORENSIC:       return "ANTIFORENSIC";
        default:                       return "UNKNOWN";
    }
}

/* -----------------------------------------------
   Alert suppression -- operator-defined substring filters against the
   rendered description, so a known-noisy finding (a specific service,
   a specific IP) can be silenced without disabling the whole module.
   ----------------------------------------------- */
BOOL ids_alert_suppressed(IdsConfig *cfg, const Alert *a) {
    for (int i = 0; i < cfg->suppress_count; i++)
        if (narsil_stristr(a->description, cfg->suppress[i]))
            return TRUE;
    return FALSE;
}

void ids_timestamp_str(time_t t, char *buf, size_t len) {
    struct tm *tm_info = localtime(&t);
    if (tm_info) strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
    else         strncpy(buf, "0000-00-00 00:00:00", len - 1);
}

/* -----------------------------------------------
   JSON escape — exported for use by report.c
   ----------------------------------------------- */
void narsil_json_escape(const char *src, char *dst, size_t dst_len) {
    if (!src) { dst[0] = '\0'; return; }
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 6 < dst_len; si++) {
        unsigned char c = (unsigned char)src[si];
        if      (c == '"')  { dst[di++] = '\\'; dst[di++] = '"';  }
        else if (c == '\\') { dst[di++] = '\\'; dst[di++] = '\\'; }
        else if (c == '\n') { dst[di++] = '\\'; dst[di++] = 'n';  }
        else if (c == '\r') { dst[di++] = '\\'; dst[di++] = 'r';  }
        else if (c == '\t') { dst[di++] = '\\'; dst[di++] = 't';  }
        else if (c < 0x20)  { di += (size_t)snprintf(dst+di, dst_len-di, "\\u%04x", c); }
        else                { dst[di++] = (char)c; }
    }
    dst[di] = '\0';
}

/* -----------------------------------------------
   Console alert output
   ----------------------------------------------- */
void ids_print_alert(const Alert *a) {
    char ts[32];
    ids_timestamp_str(a->timestamp, ts, sizeof(ts));

    WORD color = (a->severity >= SEV_HIGH) ? CON_RED :
                 (a->severity == SEV_MEDIUM) ? CON_YELLOW : CON_CYAN;

    con_color(color);
    printf("\n[!] %-8s  %s  %s\n",
           ids_severity_str(a->severity), ts, ids_alert_type_str(a->type));
    con_color(CON_WHITE);
    printf("    %s\n", a->description);
    if (a->technique_id[0]) printf("    MITRE: %s\n",          a->technique_id);
    if (a->file_path[0])    printf("    file : %s\n",           a->file_path);
    if (a->source_ip[0])    printf("    src  : %s:%lu\n",       a->source_ip, a->source_port);
    if (a->dest_ip[0])      printf("    dst  : %s:%lu\n",       a->dest_ip,   a->dest_port);
    if (a->pid)             printf("    pid  : %lu  (%s)\n",    a->pid,       a->process_name);
    if (a->parent_process[0]) printf("    parent: %s\n",        a->parent_process);
    if (a->rule_name[0])    printf("    rule : %s\n",           a->rule_name);
}

/* -----------------------------------------------
   JSONL file logging
   ----------------------------------------------- */
void ids_log_alert(IdsConfig *cfg, const Alert *a) {
    if (ids_alert_suppressed(cfg, a)) return;

    FILE *fp = fopen(cfg->log_path, "a");
    if (!fp) {
        LOG_WARN("cannot open log file: %s (err=%lu)", cfg->log_path, GetLastError());
        return;
    }

    char ts[32];
    ids_timestamp_str(a->timestamp, ts, sizeof(ts));

    /* Escape all free-text fields */
    char e_desc[MAX_DESCRIPTION * 2];
    char e_proc[MAX_PATH * 2];
    char e_cmd[1024 * 2];
    char e_file[MAX_PATH * 2];
    narsil_json_escape(a->description,  e_desc, sizeof(e_desc));
    narsil_json_escape(a->process_name, e_proc, sizeof(e_proc));
    narsil_json_escape(a->command_line, e_cmd,  sizeof(e_cmd));
    narsil_json_escape(a->file_path,    e_file, sizeof(e_file));

    fprintf(fp,
        "{\"time\":\"%s\",\"sev\":\"%s\",\"type\":\"%s\","
        "\"src\":\"%s\",\"src_port\":%lu,"
        "\"dst\":\"%s\",\"dst_port\":%lu,"
        "\"pid\":%lu,\"proc\":\"%s\","
        "\"mitre\":\"%s\",\"rule\":\"%s\","
        "\"file\":\"%s\",\"cmdline\":\"%s\","
        "\"desc\":\"%s\"}\n",
        ts,
        ids_severity_str(a->severity),
        ids_alert_type_str(a->type),
        a->source_ip, a->source_port,
        a->dest_ip,   a->dest_port,
        a->pid,       e_proc,
        a->technique_id, a->rule_name,
        e_file, e_cmd,
        e_desc);

    fclose(fp);
    LOG_DBG("alert logged -> %s [%s]", cfg->log_path, ids_alert_type_str(a->type));
}

/* -----------------------------------------------
   Main dispatch
   ----------------------------------------------- */
void ids_alert(IdsConfig *cfg, Alert *a) {
    a->timestamp = time(NULL);
    ids_print_alert(a);
    ids_log_alert(cfg, a);
}