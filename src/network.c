/*
 * network.c -- Network snapshot scanner.
 *
 * Takes a one-shot snapshot of all active TCP and UDP endpoints,
 * correlates each with the owning process, and flags:
 *   - Connections to/from blocked IPs (exact match or CIDR block)
 *   - Connections on suspicious ports
 *   - Processes connecting from staging paths (Temp, AppData, Downloads)
 *   - Listening ports on non-standard interfaces
 *   - Beaconing: repeated outbound connections to the same remote endpoint
 *     from a process running out of a staging directory
 *
 * No threads, no polling. Called once by run_scan, returns.
 */
#include "../include/ids.h"
#include "../include/report.h"

/* Well-known legitimate listening ports (not flagged as unknown service).
 * v0.1 only whitelisted a handful of TCP ports and applied the same short
 * list to UDP, so routine Windows services -- NTP client (123), NetBIOS
 * Name/Datagram (137/138), DHCP (67/68), SSDP (1900), LLMNR (5355),
 * mDNS (5353), WS-Discovery (3702) and IKE/IPsec (500/4500) -- lit up as
 * UNKNOWN_SERVICE on every scan. Those are now whitelisted by default. */
static const WORD KNOWN_PORTS[] = {
    80, 443, 135, 139, 445, 3389, 5040, 7680,
    67, 68, 123, 137, 138, 500, 1900, 3702, 4500, 5353, 5355,
    0
};

/* Minimum window between repeated connections to the same remote endpoint
   before it counts as beacon-like activity (see beacon tracker below). */
#define BEACON_MIN_HITS   4

/* -----------------------------------------------
   PID -> process name cache
   ----------------------------------------------- */
#define PID_CACHE_CAP 1024
typedef struct { DWORD pid; char name[MAX_PATH]; char path[MAX_PATH]; } PidEntry;
static PidEntry  g_pid[PID_CACHE_CAP];
static int       g_pid_n = 0;

static void pid_cache_build(void) {
    g_pid_n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("network: snapshot failed: %s", buf);
        return;
    }
    PROCESSENTRY32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (g_pid_n >= PID_CACHE_CAP) break;
            g_pid[g_pid_n].pid = pe.th32ProcessID;
            strncpy(g_pid[g_pid_n].name, pe.szExeFile, MAX_PATH - 1);

            /* Try to resolve full path */
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, pe.th32ProcessID);
            if (hp) {
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameA(hp, 0, g_pid[g_pid_n].path, &sz);
                CloseHandle(hp);
            }
            g_pid_n++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    LOG_DBG("network: pid cache built (%d entries)", g_pid_n);
}

static const PidEntry *pid_lookup(DWORD pid) {
    for (int i = 0; i < g_pid_n; i++)
        if (g_pid[i].pid == pid) return &g_pid[i];
    return NULL;
}

/* -----------------------------------------------
   Helpers
   ----------------------------------------------- */
static BOOL is_suspicious_port(IdsConfig *cfg, WORD port) {
    for (int i = 0; i < cfg->suspicious_port_count; i++)
        if (cfg->suspicious_ports[i] == port) return TRUE;
    return FALSE;
}

static BOOL is_known_port(IdsConfig *cfg, WORD port) {
    for (int i = 0; KNOWN_PORTS[i]; i++)
        if (KNOWN_PORTS[i] == port) return TRUE;
    for (int i = 0; i < cfg->known_udp_port_count; i++)
        if (cfg->known_udp_ports[i] == port) return TRUE;
    return FALSE;
}

static void ip_str(DWORD addr, char *out) {
    struct in_addr a; a.s_addr = addr;
    strncpy(out, inet_ntoa(a), MAX_IP_LEN - 1);
}

static BOOL is_loopback(const char *ip) {
    return (strncmp(ip, "127.", 4) == 0 || strcmp(ip, "::1") == 0);
}

/* -----------------------------------------------
   Emit helper
   ----------------------------------------------- */
static void emit(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl,
                 AlertType type, Severity sev,
                 const char *src, DWORD sport,
                 const char *dst, DWORD dport,
                 DWORD pid, const char *proc,
                 const char *mitre, const char *fmt, ...) {
    Alert a = {0};
    a.type       = type;
    a.severity   = sev;
    a.timestamp  = time(NULL);
    a.pid        = pid;
    a.source_port = sport;
    a.dest_port   = dport;
    if (src)  strncpy(a.source_ip,    src,  MAX_IP_LEN - 1);
    if (dst)  strncpy(a.dest_ip,      dst,  MAX_IP_LEN - 1);
    if (proc) strncpy(a.process_name, proc, MAX_PATH - 1);
    if (mitre) strncpy(a.technique_id, mitre, sizeof(a.technique_id) - 1);

    va_list ap; va_start(ap, fmt);
    vsnprintf(a.description, MAX_DESCRIPTION, fmt, ap);
    va_end(ap);

    report_add(rep, &a);
    ids_log_alert(cfg, &a);

    if (tbl) report_table_add(tbl, dst ? dst : src,
                               proc ? proc : "?",
                               ids_alert_type_str(type),
                               ENTRY_FLAGGED, a.description);
}

/* -----------------------------------------------
   Per-process distinct remote-endpoint tracker (single-snapshot heuristic).
   Narsil is scan-only -- one process, no threads, no state across runs --
   so real time-series beacon detection (fixed-interval callbacks) is out
   of reach. What one TCP snapshot *can* show is a staging-path process
   holding many simultaneous connections to distinct external IPs, which is
   the static signature of a multi-channel C2 client or an active scanner.
   ----------------------------------------------- */
#define BEACON_CAP        256
#define BEACON_MAX_REMOTE 32
typedef struct {
    DWORD pid;
    char  remote[BEACON_MAX_REMOTE][MAX_IP_LEN];
    int   n;
} BeaconTrack;
static BeaconTrack g_beacon[BEACON_CAP];
static int         g_beacon_n = 0;

static void beacon_note(DWORD pid, const char *remote_ip) {
    BeaconTrack *t = NULL;
    for (int i = 0; i < g_beacon_n; i++)
        if (g_beacon[i].pid == pid) { t = &g_beacon[i]; break; }
    if (!t) {
        if (g_beacon_n >= BEACON_CAP) return;
        t = &g_beacon[g_beacon_n++];
        t->pid = pid; t->n = 0;
    }
    for (int i = 0; i < t->n; i++)
        if (strcmp(t->remote[i], remote_ip) == 0) return;   /* already counted */
    if (t->n < BEACON_MAX_REMOTE)
        strncpy(t->remote[t->n++], remote_ip, MAX_IP_LEN - 1);
}

/* -----------------------------------------------
   TCP snapshot
   ----------------------------------------------- */
static void scan_tcp(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *table =
        (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!table) { LOG_WARN("network: tcp malloc OOM"); return; }

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("network: GetExtendedTcpTable: %s", buf);
        free(table); return;
    }

    LOG_DBG("network: TCP entries: %lu", table->dwNumEntries);

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];
        if (row->dwState != MIB_TCP_STATE_ESTAB &&
            row->dwState != MIB_TCP_STATE_LISTEN) continue;

        char src[MAX_IP_LEN] = {0}, dst[MAX_IP_LEN] = {0};
        ip_str(row->dwLocalAddr,  src);
        ip_str(row->dwRemoteAddr, dst);
        WORD sport = ntohs((WORD)row->dwLocalPort);
        WORD dport = ntohs((WORD)row->dwRemotePort);
        DWORD pid  = row->dwOwningPid;

        const PidEntry *pe = pid_lookup(pid);
        const char *name   = pe ? pe->name : "?";
        const char *path   = pe ? pe->path : "";

        LOG_DBG("network: TCP %s:%u -> %s:%u  pid=%lu (%s)",
                src, sport, dst, dport, pid, name);

        /* Add to evidence table */
        char detail[128];
        snprintf(detail, sizeof(detail), "%s:%u -> %s:%u", src, sport, dst, dport);
        report_table_add(tbl, path, name, detail, ENTRY_OK, "");

        /* Checks */
        if (narsil_ip_blocked(cfg, dst)) {
            emit(cfg, rep, tbl, ALERT_BLOCKED_IP, SEV_CRITICAL,
                 src, sport, dst, dport, pid, name, "T1071",
                 "Connection to blocked IP %s:%u by %s (pid=%lu)",
                 dst, dport, name, pid);
            continue;
        }
        if (is_suspicious_port(cfg, dport)) {
            emit(cfg, rep, tbl, ALERT_ANOMALOUS_TRAFFIC, SEV_HIGH,
                 src, sport, dst, dport, pid, name, "T1071",
                 "Connection to suspicious port %u by %s (pid=%lu)",
                 dport, name, pid);
        }
        if (path[0] && narsil_is_staging_path(path) &&
            row->dwState == MIB_TCP_STATE_ESTAB && !is_loopback(dst)) {
            emit(cfg, rep, tbl, ALERT_SUSPICIOUS_PROCESS, SEV_HIGH,
                 src, sport, dst, dport, pid, name, "T1059",
                 "Process in staging path has active connection: %s -> %s:%u",
                 path, dst, dport);
        }
        if (row->dwState == MIB_TCP_STATE_ESTAB && !is_loopback(dst))
            beacon_note(pid, dst);
    }
    free(table);
}

/* -----------------------------------------------
   UDP snapshot
   ----------------------------------------------- */
static void scan_udp(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl) {
    DWORD size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                        UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID *table =
        (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!table) { LOG_WARN("network: udp malloc OOM"); return; }

    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("network: GetExtendedUdpTable: %s", buf);
        free(table); return;
    }

    LOG_DBG("network: UDP entries: %lu", table->dwNumEntries);

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &table->table[i];
        char local[MAX_IP_LEN] = {0};
        ip_str(row->dwLocalAddr, local);
        WORD port = ntohs((WORD)row->dwLocalPort);
        DWORD pid = row->dwOwningPid;

        const PidEntry *pe = pid_lookup(pid);
        const char *name   = pe ? pe->name : "?";
        const char *path   = pe ? pe->path : "";

        LOG_DBG("network: UDP %s:%u  pid=%lu (%s)", local, port, pid, name);

        char detail[128];
        snprintf(detail, sizeof(detail), "UDP listen %s:%u", local, port);
        report_table_add(tbl, path, name, detail, ENTRY_OK, "");

        if (is_suspicious_port(cfg, port)) {
            emit(cfg, rep, tbl, ALERT_ANOMALOUS_TRAFFIC, SEV_HIGH,
                 local, port, NULL, 0, pid, name, "T1071",
                 "UDP listener on suspicious port %u by %s (pid=%lu)",
                 port, name, pid);
        }
        if (!is_loopback(local) && !is_known_port(cfg, port) && port < 1024) {
            emit(cfg, rep, tbl, ALERT_UNKNOWN_SERVICE, SEV_MEDIUM,
                 local, port, NULL, 0, pid, name, NULL,
                 "Unknown UDP service on port %u by %s (pid=%lu)",
                 port, name, pid);
        }
    }
    free(table);
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_network(IdsConfig *cfg, ScanReport *rep) {
    LOG_INFO("scan: network snapshot...");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LOG_ERR("network: WSAStartup failed (err=%lu)", GetLastError());
        return;
    }

    pid_cache_build();
    g_beacon_n = 0;

    EvidenceTable *tbl = report_table_begin(rep, "network");

    scan_tcp(cfg, rep, tbl);
    scan_udp(cfg, rep, tbl);

    /* Multi-endpoint heuristic: a staging-path process holding several
       simultaneous connections to distinct external hosts. */
    for (int i = 0; i < g_beacon_n; i++) {
        BeaconTrack *t = &g_beacon[i];
        if (t->n < BEACON_MIN_HITS) continue;

        const PidEntry *pe = pid_lookup(t->pid);
        const char *name = pe ? pe->name : "?";
        const char *path = pe ? pe->path : "";
        if (!path[0] || !narsil_is_staging_path(path)) continue;

        emit(cfg, rep, tbl, ALERT_C2_BEACON, SEV_HIGH,
             "", 0, t->remote[0], 0, t->pid, name, "T1071",
             "Process in staging path holds %d simultaneous connections to "
             "distinct external hosts (first: %s) -- possible multi-channel C2",
             t->n, t->remote[0]);
    }

    WSACleanup();
    LOG_INFO("scan: network -- done  connections=%d  flagged=%d",
             tbl->count, tbl->flagged_count);
}