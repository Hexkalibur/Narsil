/*
 * kernel.c -- Kernel driver enumeration and integrity check (SCAN only).
 *
 * Checks:
 *   1. Anonymous drivers (no file on disk)      -> CRITICAL (fileless rootkit)
 *   2. Drivers loaded from non-standard paths   -> HIGH
 *   3. Unsigned (no embedded + no catalog sig)  -> HIGH
 *   4. Tampered Authenticode signature          -> CRITICAL
 *
 * Signing strategy:
 *   Most inbox Windows drivers use catalog signing (.cat), not embedded PE
 *   signatures. WinVerifyTrust alone returns TRUST_E_NOSIGNATURE for them.
 *   We fall back to CryptCATAdmin hash lookup as the authoritative check.
 *
 * Requires: Administrator. SeLoadDriverPrivilege enabled by main.c.
 * Links: -lpsapi -lwintrust -lcrypt32
 */
#include "../include/ids.h"
#include "../include/report.h"

/* -----------------------------------------------
   Known-good driver locations (lowercase for comparison)
   ----------------------------------------------- */
static const char *LEGIT_PATHS[] = {
    "\\systemroot\\system32\\",
    "\\systemroot\\system32\\drivers\\",
    "\\systemroot\\syswow64\\",
    "\\windows\\system32\\",
    "\\windows\\system32\\drivers\\",
    "\\windows\\system32\\driverstore\\",  /* DriverStore\FileRepository\* */
    NULL
};

/* -----------------------------------------------
   Crash dump / hibernate miniport drivers.
   In-memory copies of real drivers, always unsigned by design.
   Prefix match on filename only.
   ----------------------------------------------- */
static const char *DUMP_PREFIXES[] = { "dump_", "hiber_", NULL };

static BOOL is_dump_miniport(const char *win32path) {
    const char *name = strrchr(win32path, '\\');
    name = name ? name + 1 : win32path;

    char low[64] = {0};
    size_t len = strlen(name);
    if (len >= sizeof(low)) len = sizeof(low) - 1;
    memcpy(low, name, len);
    for (char *p = low; *p; p++) *p = (char)tolower((unsigned char)*p);

    for (int i = 0; DUMP_PREFIXES[i]; i++)
        if (strncmp(low, DUMP_PREFIXES[i], strlen(DUMP_PREFIXES[i])) == 0)
            return TRUE;
    return FALSE;
}

/* -----------------------------------------------
   Returns TRUE if kpath (kernel path) is a standard
   system driver location.
   ----------------------------------------------- */
static BOOL is_legit_path(const char *kpath) {
    char low[MAX_PATH];
    size_t len = strlen(kpath);
    if (len >= MAX_PATH) len = MAX_PATH - 1;
    memcpy(low, kpath, len);
    low[len] = '\0';
    for (char *p = low; *p; p++) *p = (char)tolower((unsigned char)*p);

    for (int i = 0; LEGIT_PATHS[i]; i++)
        if (strstr(low, LEGIT_PATHS[i])) return TRUE;
    return FALSE;
}

/* -----------------------------------------------
   Resolve kernel path -> Win32 path.
   Handles:
     \SystemRoot\...         -> %SystemRoot%\...
     \Device\HarddiskVolumeN\... -> \\.\HarddiskVolumeN\... (best-effort)
     anything else           -> passed through unchanged
   ----------------------------------------------- */
static void resolve_path(const char *kpath, char *out, size_t out_len) {
    if (_strnicmp(kpath, "\\SystemRoot\\", 12) == 0) {
        char sysroot[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableA("SystemRoot", sysroot, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
            LOG_WARN("kernel: GetEnvironmentVariableA(SystemRoot) failed (err=%lu)", GetLastError());
            strncpy(sysroot, "C:\\Windows", MAX_PATH - 1);
        }
        snprintf(out, out_len, "%s\\%s", sysroot, kpath + 12);

    } else if (_strnicmp(kpath, "\\Device\\", 8) == 0) {
        /* \Device\HarddiskVolumeN\path  ->  \\.\HarddiskVolumeN\path
           WinVerifyTrust can open this via the UNC device path */
        snprintf(out, out_len, "\\\\.\\%s", kpath + 8);

    } else {
        strncpy(out, kpath, out_len - 1);
        out[out_len - 1] = '\0';
    }
}

/* Signature verification (embedded PE sig + catalog fallback) is shared
   with process.c/persistence.c via narsil_sig_verify() in util.c. */

/* -----------------------------------------------
   Emit a driver alert to both report and live log.
   Scan modules use report_add; ids_alert writes
   to the live JSONL log for cross-session traceability.
   ----------------------------------------------- */
static void emit_alert(IdsConfig *cfg, ScanReport *rep,
                       Severity sev, const char *path,
                       const char *fmt, ...) {
    Alert a = {0};
    a.type     = ALERT_SUSPICIOUS_DRIVER;
    a.severity = sev;
    strncpy(a.technique_id, "T1014", sizeof(a.technique_id) - 1);
    if (path) strncpy(a.file_path, path, MAX_PATH - 1);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a.description, MAX_DESCRIPTION, fmt, ap);
    va_end(ap);

    a.timestamp = time(NULL);
    report_add(rep, &a);          /* adds to scan report                */
    ids_log_alert(cfg, &a);       /* writes to JSONL log (not console)  */
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_kernel(IdsConfig *cfg, ScanReport *rep) {

    LOG_INFO("scan: kernel drivers -- enumerating...");

    DWORD needed = 0;
    EnumDeviceDrivers(NULL, 0, &needed);
    if (needed == 0) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_ERR("EnumDeviceDrivers sizing failed: %s", buf);
        return;
    }

    LPVOID *drv = (LPVOID *)malloc(needed);
    if (!drv) { LOG_ERR("kernel: malloc(%lu) OOM", needed); return; }

    if (!EnumDeviceDrivers(drv, needed, &needed)) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_ERR("EnumDeviceDrivers failed: %s", buf);
        free(drv); return;
    }

    DWORD count = needed / (DWORD)sizeof(LPVOID);
    LOG_INFO("scan: %lu kernel modules found", count);

    /* Open evidence table — every driver gets a row */
    EvidenceTable *tbl = report_table_begin(rep, "kernel_drivers");

    int flagged = 0;
    int skipped = 0;

    for (DWORD i = 0; i < count; i++) {
        char kpath[MAX_PATH]   = {0};
        char w32path[MAX_PATH] = {0};
        char base_name[128]    = {0};

        /* Anonymous driver */
        if (!GetDeviceDriverFileNameA(drv[i], kpath, MAX_PATH) || !kpath[0]) {
            snprintf(base_name, sizeof(base_name), "<anonymous@%p>", drv[i]);
            LOG_WARN("kernel: anonymous driver at base %p", drv[i]);

            emit_alert(cfg, rep, SEV_CRITICAL, NULL,
                "Anonymous kernel driver base=%p -- no file on disk (fileless rootkit?)",
                drv[i]);

            report_table_add(tbl, "", base_name, "no file on disk",
                             ENTRY_FLAGGED, "anonymous driver -- possible fileless rootkit");
            flagged++;
            continue;
        }

        resolve_path(kpath, w32path, sizeof(w32path));

        /* Extract short name for display */
        const char *fname = strrchr(w32path, '\\');
        strncpy(base_name, fname ? fname + 1 : w32path, sizeof(base_name) - 1);

        LOG_DBG("kernel: [%lu/%lu] %s", i + 1, count, kpath);

        /* Crash dump / hibernate miniport */
        if (is_dump_miniport(w32path)) {
            LOG_DBG("kernel: skip dump miniport: %s", w32path);
            report_table_add(tbl, w32path, base_name, "dump/hiber miniport",
                             ENTRY_SKIPPED, "in-memory copy of real driver, unsigned by design");
            skipped++;
            continue;
        }

        /* Non-standard path */
        BOOL bad_path = !is_legit_path(kpath);
        if (bad_path) {
            LOG_WARN("kernel: non-standard path: %s", w32path);
            emit_alert(cfg, rep, SEV_HIGH, w32path,
                "Driver from non-standard path: %s", w32path);
            flagged++;
        }

        /* Signature check */
        NarsilSig sig  = narsil_sig_verify(w32path);
        const char *sig_str = narsil_sig_str(sig);

        if (sig == NSIG_UNSIGNED) {
            emit_alert(cfg, rep, SEV_HIGH, w32path,
                "Unsigned driver: %s", w32path);
            report_table_add(tbl, w32path, base_name, sig_str,
                             ENTRY_FLAGGED, "no valid signature found");
            flagged++;
        } else if (sig == NSIG_INVALID) {
            emit_alert(cfg, rep, SEV_CRITICAL, w32path,
                "Tampered driver (invalid signature): %s", w32path);
            report_table_add(tbl, w32path, base_name, sig_str,
                             ENTRY_FLAGGED, "signature verification failed -- possible tampering");
            flagged++;
        } else if (bad_path) {
            report_table_add(tbl, w32path, base_name, sig_str,
                             ENTRY_WARN, "valid signature but loaded from non-standard path");
        } else {
            report_table_add(tbl, w32path, base_name, sig_str,
                             ENTRY_OK, "");
        }
    }

    LOG_INFO("scan: kernel drivers -- done  total=%lu  flagged=%d  skipped=%d",
             count, flagged, skipped);
    free(drv);
}