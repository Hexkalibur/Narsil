#ifndef IDS_H
#define IDS_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <psapi.h>
#include <ctype.h>

#ifdef _MSC_VER
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "wevtapi.lib")
#endif

/* -----------------------------------------------
   Version
   ----------------------------------------------- */
#define IDS_VERSION  "0.2.0"

/* -----------------------------------------------
   Limits
   ----------------------------------------------- */
#define MAX_LOG_PATH         512
#define MAX_RULE_NAME        64
#define MAX_DESCRIPTION      256
#define MAX_IP_LEN           46
#define MAX_BLOCKED_IPS      256
#define MAX_SUSPICIOUS_PORTS 64
#define MAX_ALLOW_PROCS      64
#define MAX_SUPPRESS         128
#define MAX_SUPPRESS_LEN     128
#define MAX_KNOWN_PORTS      128
#define ALERT_LOG_FILE       "ids_alerts.jsonl"

/* -----------------------------------------------
   Logging macros
   ----------------------------------------------- */
extern BOOL g_verbose;

#define LOG_INFO(fmt, ...)  fprintf(stdout, "[*] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)   do { if (g_verbose) fprintf(stdout, "[D] " fmt "\n", ##__VA_ARGS__); } while(0)

#define WIN_ERR_BUF 256
#define WIN_ERR_STR(code, buf) \
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
                   NULL, (code), 0, (buf), WIN_ERR_BUF, NULL)

/* -----------------------------------------------
   Safe string copy
   ----------------------------------------------- */
#define SAFE_COPY(dst, src) \
    do { \
        size_t _n = sizeof(dst) - 1; \
        memcpy((dst), (src), _n); \
        (dst)[_n] = '\0'; \
    } while (0)

/* -----------------------------------------------
   Severity
   ----------------------------------------------- */
typedef enum {
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4
} Severity;

/* -----------------------------------------------
   Alert types
   ----------------------------------------------- */
typedef enum {
    /* Network */
    ALERT_PORT_SCAN,
    ALERT_BLOCKED_IP,
    ALERT_ANOMALOUS_TRAFFIC,
    ALERT_UNKNOWN_SERVICE,
    ALERT_C2_BEACON,
    /* Process */
    ALERT_SUSPICIOUS_PROCESS,
    ALERT_LOLBIN,
    ALERT_CREDENTIAL_ACCESS,
    ALERT_SUSPICIOUS_CMDLINE,
    /* Events */
    ALERT_BRUTE_FORCE,
    ALERT_SUSPICIOUS_EVENT,
    ALERT_DEFENDER_EVENT,
    /* Kernel / rootkit */
    ALERT_SUSPICIOUS_DRIVER,
    ALERT_HIDDEN_PROCESS,
    /* Persistence */
    ALERT_PERSISTENCE,
    /* Memory */
    ALERT_MEMORY_ANOMALY,
    ALERT_INJECTED_PE,
    ALERT_INJECTED_THREAD,
    ALERT_YARA_MATCH,
    /* Files */
    ALERT_FIM,
    ALERT_SENSITIVE_DATA,
    /* Platform */
    ALERT_PLATFORM_INTEGRITY,
    ALERT_KEYLOGGER,
    ALERT_CLIPBOARD,
    ALERT_SCREEN_CAPTURE,
    ALERT_ANTIFORENSIC,
} AlertType;

/* -----------------------------------------------
   Alert struct
   ----------------------------------------------- */
typedef struct {
    time_t    timestamp;
    AlertType type;
    Severity  severity;
    char      source_ip[MAX_IP_LEN];
    DWORD     source_port;
    char      dest_ip[MAX_IP_LEN];
    DWORD     dest_port;
    DWORD     pid;
    char      process_name[MAX_PATH];
    char      description[MAX_DESCRIPTION];
    /* Extended */
    char      command_line[512];
    char      parent_process[MAX_PATH];
    char      technique_id[16];
    char      rule_name[64];
    char      file_path[MAX_PATH];
} Alert;

/* -----------------------------------------------
   Config
   ----------------------------------------------- */
typedef struct {
    char    log_path[MAX_LOG_PATH];
    char    blocked_ips[MAX_BLOCKED_IPS][MAX_IP_LEN];
    int     blocked_ip_count;
    /* CIDR block entries (IPv4), parsed from "a.b.c.d/nn" */
    struct { DWORD net; DWORD mask; } blocked_nets[MAX_BLOCKED_IPS];
    int     blocked_net_count;
    WORD    suspicious_ports[MAX_SUSPICIOUS_PORTS];
    int     suspicious_port_count;
    BOOL    verbose;
    /* Per-module scan toggles (default TRUE). Let the operator skip
       slow or noisy modules from the config file. */
    BOOL    scan_kernel;
    BOOL    scan_rootkit;
    BOOL    scan_persistence;
    BOOL    scan_processes;
    BOOL    scan_memory;
    BOOL    scan_network;
    BOOL    scan_events;
    /* v0.2 -- noise control */
    char    allow_rwx[MAX_ALLOW_PROCS][64];   /* processes allowed RWX memory */
    int     allow_rwx_count;
    char    suppress[MAX_SUPPRESS][MAX_SUPPRESS_LEN]; /* alert substring filters */
    int     suppress_count;
    WORD    known_udp_ports[MAX_KNOWN_PORTS]; /* extra known UDP services   */
    int     known_udp_port_count;
    WORD    known_tcp_ports[MAX_KNOWN_PORTS]; /* extra known TCP services   */
    int     known_tcp_port_count;
    BOOL    memory_strict;                    /* v0.1 behavior: alert every RWX */
    int     events_hours_back;                /* event-log lookback (default 24) */
    SRWLOCK config_lock;
} IdsConfig;

/* Set once by main(); used for suppression checks in report_add(), which
   has no cfg parameter of its own. */
extern IdsConfig *g_active_cfg;

/* -----------------------------------------------
   Shared helpers (util.c)
   ----------------------------------------------- */

/* Authenticode status: embedded PE signature first, catalog fallback. */
typedef enum { NSIG_VALID, NSIG_UNSIGNED, NSIG_INVALID } NarsilSig;

/* Suspicious command-line / script pattern table entry. */
typedef struct {
    const char *pattern;   /* lowercase substring to match  */
    Severity    sev;
    const char *mitre;     /* MITRE ATT&CK technique        */
    const char *why;       /* human-readable classification */
} NarsilPattern;

const char *narsil_stristr(const char *hay, const char *needle);
void        narsil_lower_copy(char *dst, const char *src, size_t dst_len);
BOOL        narsil_is_staging_path(const char *path);
NarsilSig   narsil_sig_verify(const char *path);
const char *narsil_sig_str(NarsilSig s);
void        narsil_get_exe_path(DWORD pid, char *out, DWORD out_sz);
BOOL        narsil_get_cmdline(DWORD pid, char *out, size_t out_len);
const NarsilPattern *narsil_match_pattern(const char *text);
BOOL        narsil_ip_blocked(IdsConfig *cfg, const char *ip);

/* -----------------------------------------------
   Forward declaration for ScanReport
   (full definition in report.h)
   ----------------------------------------------- */
typedef struct ScanReport ScanReport;

/* -----------------------------------------------
   Function prototypes
   ----------------------------------------------- */

/* Config */
IdsConfig  *ids_config_create(void);
BOOL        ids_config_load(IdsConfig *cfg, const char *path);
void        ids_config_free(IdsConfig *cfg);

/* Alert */
void        ids_alert(IdsConfig *cfg, Alert *a);
void        ids_log_alert(IdsConfig *cfg, const Alert *a);
void        ids_print_alert(const Alert *a);
BOOL        ids_alert_suppressed(IdsConfig *cfg, const Alert *a);
void        narsil_json_escape(const char *src, char *dst, size_t dst_len);
const char *ids_severity_str(Severity s);
const char *ids_alert_type_str(AlertType t);
void        ids_timestamp_str(time_t t, char *buf, size_t len);

/* Scan modules */
void ids_scan_kernel     (IdsConfig *cfg, ScanReport *rep);
void ids_scan_rootkit    (IdsConfig *cfg, ScanReport *rep);
void ids_scan_memory     (IdsConfig *cfg, ScanReport *rep, const char *yara_rules);
void ids_scan_processes  (IdsConfig *cfg, ScanReport *rep, const char *yara_rules);
void ids_scan_network    (IdsConfig *cfg, ScanReport *rep);
void ids_scan_events     (IdsConfig *cfg, ScanReport *rep);
void ids_scan_persistence(IdsConfig *cfg, ScanReport *rep);

#endif /* IDS_H */
