/*
 * process.c -- Process scanner.
 *
 * For every running process, checks:
 *   1. Name against known-bad list (tier 1)
 *   2. Command line against the suspicious pattern table (tier 2, v0.2)
 *   3. Parent-child anomalies (Office/browser -> shell) (tier 3)
 *   4. Executable path — staging directories (tier 4)
 *   5. Authenticode signature (tier 5)
 *   6. Integrity level (LOW = sandboxed/suspicious if not browser)
 *
 * No threads. Called once by run_scan, returns.
 */
#include "../include/ids.h"
#include "../include/report.h"

/* -----------------------------------------------
   Tier 1 — known-bad process names
   ----------------------------------------------- */
static const char *BAD_NAMES[] = {
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe",
    "psexec.exe",   "psexesvc.exe",    "wce.exe","fgdump.exe",
    "procdump.exe", "pwdump.exe",      "lazagne.exe",
    NULL
};

/* -----------------------------------------------
   Parent-child anomaly table
   Parent -> child combos that indicate malicious activity
   ----------------------------------------------- */
typedef struct { const char *parent; const char *child; Severity sev; const char *why; } ParentChildRule;
static const ParentChildRule PC_RULES[] = {
    { "winword.exe",   "cmd.exe",        SEV_CRITICAL, "Office spawning shell" },
    { "winword.exe",   "powershell.exe", SEV_CRITICAL, "Office spawning PowerShell" },
    { "winword.exe",   "wscript.exe",    SEV_CRITICAL, "Office spawning script host" },
    { "excel.exe",     "cmd.exe",        SEV_CRITICAL, "Office spawning shell" },
    { "excel.exe",     "powershell.exe", SEV_CRITICAL, "Office spawning PowerShell" },
    { "outlook.exe",   "cmd.exe",        SEV_CRITICAL, "Office spawning shell" },
    { "outlook.exe",   "powershell.exe", SEV_CRITICAL, "Office spawning PowerShell" },
    { "svchost.exe",   "cmd.exe",        SEV_HIGH,     "svchost spawning shell" },
    { "svchost.exe",   "powershell.exe", SEV_HIGH,     "svchost spawning PowerShell" },
    { "explorer.exe",  "powershell.exe", SEV_HIGH,     "Explorer spawning PowerShell" },
    { "mshta.exe",     "cmd.exe",        SEV_CRITICAL, "mshta spawning shell" },
    { "wscript.exe",   "cmd.exe",        SEV_HIGH,     "Script host spawning shell" },
    { "cscript.exe",   "cmd.exe",        SEV_HIGH,     "Script host spawning shell" },
    { NULL, NULL, 0, NULL }
};

/* -----------------------------------------------
   Integrity level of a process
   ----------------------------------------------- */
static const char *get_integrity(DWORD pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return "unknown";
    HANDLE tok = NULL;
    if (!OpenProcessToken(hp, TOKEN_QUERY, &tok)) { CloseHandle(hp); return "unknown"; }
    CloseHandle(hp);

    DWORD sz = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &sz);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(sz);
    const char *level = "unknown";
    if (tml && GetTokenInformation(tok, TokenIntegrityLevel, tml, sz, &sz)) {
        DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
                     *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        level = rid < SECURITY_MANDATORY_MEDIUM_RID ? "LOW"    :
                rid < SECURITY_MANDATORY_HIGH_RID   ? "MEDIUM" :
                rid < SECURITY_MANDATORY_SYSTEM_RID ? "HIGH"   : "SYSTEM";
    }
    free(tml);
    CloseHandle(tok);
    return level;
}

/* -----------------------------------------------
   Helpers
   ----------------------------------------------- */
static void get_parent_name(DWORD parent_pid, char *out) {
    out[0] = '\0';
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe; memset(&pe, 0, sizeof(pe)); pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == parent_pid) {
                strncpy(out, pe.szExeFile, MAX_PATH - 1);
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static void emit(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl,
                 AlertType type, Severity sev, DWORD pid,
                 const char *name, const char *path,
                 const char *mitre, EntryStatus es,
                 const char *fmt, ...) {
    Alert a = {0};
    a.type      = type;
    a.severity  = sev;
    a.timestamp = time(NULL);
    a.pid       = pid;
    if (name) strncpy(a.process_name, name, MAX_PATH - 1);
    if (path) strncpy(a.file_path,    path, MAX_PATH - 1);
    if (mitre) strncpy(a.technique_id, mitre, sizeof(a.technique_id) - 1);

    va_list ap; va_start(ap, fmt);
    vsnprintf(a.description, MAX_DESCRIPTION, fmt, ap);
    va_end(ap);

    report_add(rep, &a);
    ids_log_alert(cfg, &a);

    if (tbl) report_table_add(tbl, path ? path : "",
                               name ? name : "?",
                               ids_alert_type_str(type),
                               es, a.description);
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_processes(IdsConfig *cfg, ScanReport *rep,
                        const char *yara_rules) {
    (void)yara_rules; /* used by memory.c when implemented */
    LOG_INFO("scan: processes...");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_ERR("process: snapshot failed: %s", buf);
        return;
    }

    EvidenceTable *tbl = report_table_begin(rep, "processes");

    PROCESSENTRY32 pe; memset(&pe, 0, sizeof(pe)); pe.dwSize = sizeof(pe);
    int total = 0, flagged = 0;

    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        LOG_WARN("process: Process32First failed");
        return;
    }

    do {
        total++;
        DWORD  pid    = pe.th32ProcessID;
        char  *name   = pe.szExeFile;
        char   path[MAX_PATH] = {0};
        char   parent_name[MAX_PATH] = {0};
        char   lower_name[MAX_PATH]  = {0};

        if (pid == 0 || pid == 4) {   /* System Idle / System */
            report_table_add(tbl, "", name, "system process", ENTRY_SKIPPED, "");
            continue;
        }

        narsil_get_exe_path(pid, path, MAX_PATH);
        get_parent_name(pe.th32ParentProcessID, parent_name);

        /* Lowercase name for comparison */
        strncpy(lower_name, name, MAX_PATH - 1);
        for (char *p = lower_name; *p; p++) *p = (char)tolower((unsigned char)*p);

        LOG_DBG("process: [%lu] %s  parent=%s  path=%s",
                pid, name, parent_name, path);

        BOOL bad = FALSE;

        /* Tier 1 — known bad name */
        for (int i = 0; BAD_NAMES[i]; i++) {
            if (strcmp(lower_name, BAD_NAMES[i]) == 0) {
                emit(cfg, rep, tbl, ALERT_SUSPICIOUS_PROCESS, SEV_CRITICAL,
                     pid, name, path, "T1036", ENTRY_FLAGGED,
                     "Known-bad process: %.64s  integrity=%s  parent=%.64s(pid=%lu)",
                     name, get_integrity(pid), parent_name, pe.th32ParentProcessID);
                bad = TRUE; flagged++;
                break;
            }
        }
        if (bad) continue;

        /* Tier 2 — command-line pattern match (v0.2). Cross-process
           command-line retrieval is best-effort (see narsil_get_cmdline);
           silently skipped if the PEB read fails. */
        char cmdline[512] = {0};
        if (narsil_get_cmdline(pid, cmdline, sizeof(cmdline))) {
            const NarsilPattern *m = narsil_match_pattern(cmdline);
            if (m) {
                emit(cfg, rep, tbl, ALERT_SUSPICIOUS_CMDLINE, m->sev,
                     pid, name, path, m->mitre, ENTRY_FLAGGED,
                     "%s: %s (pid=%lu) cmdline: %.200s",
                     m->why, name, pid, cmdline);
                bad = TRUE; flagged++;
            }
        }
        if (bad) continue;

        /* Tier 3 — parent-child anomaly */
        char lower_parent[MAX_PATH] = {0};
        strncpy(lower_parent, parent_name, MAX_PATH - 1);
        for (char *p = lower_parent; *p; p++) *p = (char)tolower((unsigned char)*p);

        for (int i = 0; PC_RULES[i].parent; i++) {
            if (strcmp(lower_parent, PC_RULES[i].parent) == 0 &&
                strcmp(lower_name,   PC_RULES[i].child)  == 0) {
                emit(cfg, rep, tbl, ALERT_LOLBIN, PC_RULES[i].sev,
                     pid, name, path, "T1059", ENTRY_FLAGGED,
                     "%s: %s -> %s (pid=%lu)",
                     PC_RULES[i].why, parent_name, name, pid);
                bad = TRUE; flagged++;
                break;
            }
        }
        if (bad) continue;

        /* Tier 4 — staging path */
        if (path[0] && narsil_is_staging_path(path)) {
            NarsilSig sig = narsil_sig_verify(path);
            Severity  sev = (sig == NSIG_INVALID)  ? SEV_CRITICAL :
                            (sig == NSIG_UNSIGNED)  ? SEV_HIGH     : SEV_MEDIUM;
            emit(cfg, rep, tbl, ALERT_SUSPICIOUS_PROCESS, sev,
                 pid, name, path, "T1059", ENTRY_FLAGGED,
                 "Process in staging path (%s sig): %.64s  integrity=%s",
                 narsil_sig_str(sig), path, get_integrity(pid));
            flagged++;
            continue;
        }

        /* Tier 5 — unsigned binary outside staging (lower severity) */
        if (path[0]) {
            NarsilSig sig = narsil_sig_verify(path);
            if (sig == NSIG_INVALID) {
                emit(cfg, rep, tbl, ALERT_SUSPICIOUS_PROCESS, SEV_HIGH,
                     pid, name, path, "T1036", ENTRY_FLAGGED,
                     "Tampered binary: %.64s  integrity=%s",
                     path, get_integrity(pid));
                flagged++;
                continue;
            }
            const char *sig_str = (sig == NSIG_VALID) ? "signed (embedded/catalog)"
                                                        : "unsigned";
            report_table_add(tbl, path, name, sig_str, ENTRY_OK, "");
        } else {
            report_table_add(tbl, "", name, "path unavailable", ENTRY_OK, "");
        }

    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    LOG_INFO("scan: processes -- done  total=%d  flagged=%d", total, flagged);
}