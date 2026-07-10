/*
 * persistence.c -- Persistence mechanism scanner (SCAN only).
 *
 * Enumerates the most abused autostart extensibility points and flags
 * entries whose backing executable is missing, or lives in a
 * user-writable staging directory (Temp, AppData, Downloads, ...):
 *
 *   1. Registry Run / RunOnce keys (HKLM + HKCU)
 *   2. Winlogon Userinit / Shell (HKLM) -- flag deviation from defaults
 *   3. Win32 services -- flag ImagePath in staging locations / missing file
 *
 * Alert type: ALERT_PERSISTENCE   MITRE: T1547 / T1543 / T1037
 *
 * Links: -ladvapi32
 */
#include "../include/ids.h"
#include "../include/report.h"

static void to_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* Pull the executable path out of a command line:
   "C:\a b\x.exe" -foo   ->  C:\a b\x.exe
   C:\a\x.exe -foo        ->  C:\a\x.exe
   Expands leading %EnvVar% components. */
static void extract_exe(const char *cmd, char *out, size_t out_len) {
    char raw[MAX_PATH] = {0};
    size_t i = 0;

    while (*cmd == ' ' || *cmd == '\t') cmd++;

    if (*cmd == '"') {
        cmd++;
        while (*cmd && *cmd != '"' && i < sizeof(raw) - 1) raw[i++] = *cmd++;
    } else {
        while (*cmd && *cmd != ' ' && i < sizeof(raw) - 1) raw[i++] = *cmd++;
    }
    raw[i] = '\0';

    /* Expand environment variables (%SystemRoot% etc.) */
    if (strchr(raw, '%')) {
        if (ExpandEnvironmentStringsA(raw, out, (DWORD)out_len) == 0) {
            strncpy(out, raw, out_len - 1);
            out[out_len - 1] = '\0';
        }
    } else {
        strncpy(out, raw, out_len - 1);
        out[out_len - 1] = '\0';
    }
}

static BOOL file_exists(const char *path) {
    if (!path[0]) return FALSE;
    DWORD attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES &&
           !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

/* -----------------------------------------------
   Emit
   ----------------------------------------------- */
static void emit(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl,
                 Severity sev, const char *mitre,
                 const char *name, const char *path,
                 EntryStatus es, const char *reason,
                 const char *fmt, ...) {
    Alert a = {0};
    a.type      = ALERT_PERSISTENCE;
    a.severity  = sev;
    a.timestamp = time(NULL);
    if (name) strncpy(a.process_name, name, MAX_PATH - 1);
    if (path) strncpy(a.file_path,    path, MAX_PATH - 1);
    if (mitre) strncpy(a.technique_id, mitre, sizeof(a.technique_id) - 1);

    va_list ap; va_start(ap, fmt);
    vsnprintf(a.description, MAX_DESCRIPTION, fmt, ap);
    va_end(ap);

    report_add(rep, &a);
    ids_log_alert(cfg, &a);
    if (tbl) report_table_add(tbl, path ? path : "", name ? name : "?",
                              ids_alert_type_str(ALERT_PERSISTENCE), es, reason);
}

/* Classify an autostart target and record it. */
static void inspect_target(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl,
                           const char *origin, const char *name,
                           const char *command, const char *mitre) {
    char exe[MAX_PATH] = {0};
    extract_exe(command, exe, sizeof(exe));

    char detail[MAX_PATH];
    snprintf(detail, sizeof(detail), "%s -> %s", origin, command);

    if (exe[0] && narsil_is_staging_path(exe)) {
        emit(cfg, rep, tbl, SEV_HIGH, mitre, name, exe, ENTRY_FLAGGED,
             "autostart from staging path",
             "Persistence via %s: '%s' runs %s (staging path)",
             origin, name, exe);
    } else if (exe[0] && !file_exists(exe)) {
        emit(cfg, rep, tbl, SEV_MEDIUM, mitre, name, exe, ENTRY_WARN,
             "autostart target missing on disk",
             "Persistence via %s: '%s' points at missing file %s",
             origin, name, exe);
    } else if (tbl) {
        report_table_add(tbl, exe, name, detail, ENTRY_OK, "");
    }
}

/* -----------------------------------------------
   Registry Run / RunOnce keys
   ----------------------------------------------- */
static void scan_run_key(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl,
                         HKEY root, const char *root_name, const char *subkey) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;   /* key absent is normal */

    char origin[256];
    snprintf(origin, sizeof(origin), "%s\\%s", root_name, subkey);

    DWORD idx = 0;
    char  valname[256];
    char  data[1024];
    for (;;) {
        DWORD name_len = sizeof(valname);
        DWORD data_len = sizeof(data);
        DWORD type = 0;
        LONG rc = RegEnumValueA(hk, idx++, valname, &name_len, NULL, &type,
                                (LPBYTE)data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        data[sizeof(data) - 1] = '\0';

        inspect_target(cfg, rep, tbl, origin, valname, data, "T1547");
    }
    RegCloseKey(hk);
}

/* -----------------------------------------------
   Winlogon Userinit / Shell
   ----------------------------------------------- */
static void scan_winlogon(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl) {
    static const char *KEY =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KEY, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return;

    struct { const char *value; const char *expect_substr; } checks[] = {
        { "Userinit", "userinit.exe" },
        { "Shell",    "explorer.exe" },
    };

    for (int i = 0; i < 2; i++) {
        char data[1024] = {0};
        DWORD len = sizeof(data), type = 0;
        if (RegQueryValueExA(hk, checks[i].value, NULL, &type,
                             (LPBYTE)data, &len) != ERROR_SUCCESS)
            continue;
        data[sizeof(data) - 1] = '\0';

        char low[1024];
        strncpy(low, data, sizeof(low) - 1); low[sizeof(low) - 1] = '\0';
        to_lower(low);

        char origin[128];
        snprintf(origin, sizeof(origin), "Winlogon\\%s", checks[i].value);

        if (!strstr(low, checks[i].expect_substr)) {
            emit(cfg, rep, tbl, SEV_CRITICAL, "T1547", checks[i].value, data,
                 ENTRY_FLAGGED, "Winlogon key deviates from default",
                 "Winlogon %s hijacked: '%s' (expected to contain %s)",
                 checks[i].value, data, checks[i].expect_substr);
        } else {
            report_table_add(tbl, data, checks[i].value, origin, ENTRY_OK, "");
        }
    }
    RegCloseKey(hk);
}

/* -----------------------------------------------
   Win32 services
   ----------------------------------------------- */
static void scan_services(IdsConfig *cfg, ScanReport *rep, EvidenceTable *tbl) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("persistence: OpenSCManager failed: %s", buf);
        return;
    }

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &needed, &count,
                          &resume, NULL);
    if (needed == 0) { CloseServiceHandle(scm); return; }

    BYTE *buf = (BYTE *)malloc(needed);
    if (!buf) { CloseServiceHandle(scm); LOG_WARN("persistence: svc OOM"); return; }

    if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buf, needed, &needed,
                               &count, &resume, NULL)) {
        char e[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), e);
        LOG_WARN("persistence: EnumServicesStatusEx failed: %s", e);
        free(buf); CloseServiceHandle(scm); return;
    }

    ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)buf;
    for (DWORD i = 0; i < count; i++) {
        const char *sname = svc[i].lpServiceName ? svc[i].lpServiceName : "?";

        SC_HANDLE hs = OpenServiceA(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hs) continue;

        DWORD cfg_need = 0;
        QueryServiceConfigA(hs, NULL, 0, &cfg_need);
        QUERY_SERVICE_CONFIGA *qsc = (QUERY_SERVICE_CONFIGA *)malloc(cfg_need);
        if (qsc && QueryServiceConfigA(hs, qsc, cfg_need, &cfg_need)) {
            const char *binpath = qsc->lpBinaryPathName ? qsc->lpBinaryPathName : "";
            char exe[MAX_PATH] = {0};
            extract_exe(binpath, exe, sizeof(exe));

            if (exe[0] && narsil_is_staging_path(exe)) {
                emit(cfg, rep, tbl, SEV_HIGH, "T1543", sname, exe, ENTRY_FLAGGED,
                     "service binary in staging path",
                     "Service '%s' runs from staging path: %s", sname, exe);
            } else if (exe[0] && _strnicmp(exe, "\\systemroot", 11) != 0 &&
                       !file_exists(exe)) {
                emit(cfg, rep, tbl, SEV_MEDIUM, "T1543", sname, exe, ENTRY_WARN,
                     "service binary missing on disk",
                     "Service '%s' points at missing binary: %s", sname, exe);
            }
            /* clean services are numerous; don't flood the evidence table */
        }
        free(qsc);
        CloseServiceHandle(hs);
    }

    free(buf);
    CloseServiceHandle(scm);
    LOG_DBG("persistence: %lu services enumerated", count);
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_persistence(IdsConfig *cfg, ScanReport *rep) {
    LOG_INFO("scan: persistence (run keys, winlogon, services)...");

    EvidenceTable *tbl = report_table_begin(rep, "persistence");

    static const char *RUN_KEYS[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        NULL
    };

    for (int i = 0; RUN_KEYS[i]; i++) {
        scan_run_key(cfg, rep, tbl, HKEY_LOCAL_MACHINE, "HKLM", RUN_KEYS[i]);
        scan_run_key(cfg, rep, tbl, HKEY_CURRENT_USER,  "HKCU", RUN_KEYS[i]);
    }

    scan_winlogon(cfg, rep, tbl);
    scan_services(cfg, rep, tbl);

    LOG_INFO("scan: persistence -- done  entries=%d  flagged=%d",
             tbl ? tbl->count : 0, tbl ? tbl->flagged_count : 0);
}
