/*
 * main.c -- Narsil entry point.
 *
 * Usage:
 *   narsil.exe [-c <conf>] [-r <rules.yar>] [-o <report.md>] [-v] [-h]
 *
 * Narsil is a scan-only security tool. It performs a deep one-shot
 * analysis of the system and exits. No resident process, no threads.
 *
 * Requires Administrator privileges.
 */
#include "../include/ids.h"
#include "../include/report.h"

BOOL   g_verbose = FALSE;

/* -----------------------------------------------
   Privilege helpers
   ----------------------------------------------- */
static BOOL is_elevated(void) {
    BOOL elevated = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te;
        DWORD sz = sizeof(te);
        if (GetTokenInformation(tok, TokenElevation, &te, sz, &sz))
            elevated = (BOOL)te.TokenIsElevated;
        CloseHandle(tok);
    }
    return elevated;
}

static BOOL enable_privilege(const char *name) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FALSE;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid)
           && AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL)
           && GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

static void acquire_privileges(void) {
    static const struct { const char *name; const char *module; } privs[] = {
        { SE_DEBUG_NAME,              "memory / credential"       },
        { SE_LOAD_DRIVER_NAME,        "kernel driver enumeration" },
        { SE_SYSTEM_PROFILE_NAME,     "ETW"                       },
        { SE_BACKUP_NAME,             "FIM locked-file read"      },
        { SE_SYSTEM_ENVIRONMENT_NAME, "platform attestation"      },
    };
    for (int i = 0; i < (int)(sizeof privs / sizeof *privs); i++) {
        if (enable_privilege(privs[i].name))
            LOG_DBG("privilege OK    : %-36s [%s]", privs[i].name, privs[i].module);
        else
            LOG_WARN("privilege DENIED: %-36s -- %s may be limited", privs[i].name, privs[i].module);
    }
}

/* -----------------------------------------------
   Help
   ----------------------------------------------- */
static void print_help(const char *prog) {
    printf(
        "Narsil v%s -- Advanced Security Scanner\n\n"
        "Usage: %s [-c <conf>] [-r <rules.yar>] [-o <report.md>] [-v] [-h]\n\n"
        "Options:\n"
        "  -c <conf>      Config file (blocked IPs, suspicious ports)\n"
        "  -r <rules.yar> YARA rules file for memory and file scanning\n"
        "  -o <report.md> Report output path (default: narsil_report.md)\n"
        "  -v             Verbose / debug output\n"
        "  -h             This help\n\n"
        "Scan modules (executed in order):\n"
        "  kernel       Driver enumeration + signature verification\n"
        "  rootkit      Hidden process detection (NtQSI vs Toolhelp)\n"
        "  persistence  Run keys, services, scheduled tasks, WMI\n"
        "  processes    Process name, path, parent-child, signature\n"
        "  memory       Hollowing, injection, RWX regions (YARA)\n"
        "  network      Active connections snapshot\n"
        "  events       Recent Security / System event log entries\n\n"
        "Output:\n"
        "  <report>.md           Human-readable report\n"
        "  <report>.jsonl        Machine-readable alerts (SIEM-ready)\n"
        "  <report>_<module>.csv Full evidence list per module\n\n"
        "Requires Administrator privileges.\n\n",
        IDS_VERSION, prog);
}

/* -----------------------------------------------
   Entry point
   ----------------------------------------------- */
int main(int argc, char *argv[]) {

    if (!is_elevated()) {
        LOG_ERR("Narsil requires Administrator privileges.\n"
                "    Re-run from an elevated command prompt.");
        return 1;
    }

    acquire_privileges();

    /* Defaults */
    const char *conf_file   = NULL;
    const char *yara_rules  = NULL;
    const char *report_path = "narsil_report.md";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help(argv[0]); return 0;
        } else if (!strcmp(argv[i], "-v")) {
            g_verbose = TRUE;
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            conf_file = argv[++i];
        } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            yara_rules = argv[++i];
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            report_path = argv[++i];
        } else {
            LOG_ERR("unknown argument: %s", argv[i]);
            print_help(argv[0]); return 1;
        }
    }

    IdsConfig *cfg = ids_config_create();
    if (!cfg) { LOG_ERR("failed to allocate config"); return 1; }

    if (conf_file) {
        if (!ids_config_load(cfg, conf_file)) {
            LOG_ERR("could not load config: %s", conf_file);
            ids_config_free(cfg); return 1;
        }
        LOG_INFO("config loaded: %s", conf_file);
    }

    cfg->verbose = g_verbose;

    /* Derive JSONL path from report path */
    char jsonl[MAX_LOG_PATH];
    strncpy(jsonl, report_path, MAX_LOG_PATH - 1);
    char *dot = strrchr(jsonl, '.');
    if (dot) snprintf(dot,  MAX_LOG_PATH - (int)(dot - jsonl), ".jsonl");
    else     strncat(jsonl, ".jsonl", MAX_LOG_PATH - strlen(jsonl) - 1);

    ScanReport *rep = report_create(report_path, jsonl);
    if (!rep) { LOG_ERR("failed to create report"); ids_config_free(cfg); return 1; }

    LOG_INFO("Narsil v%s -- scan started", IDS_VERSION);
    LOG_INFO("report : %s", report_path);
    LOG_INFO("JSONL  : %s\n", jsonl);

    /* -----------------------------------------------
       Scan modules: sequential, no threads
       ----------------------------------------------- */
    if (cfg->scan_kernel)      ids_scan_kernel     (cfg, rep);
    if (cfg->scan_rootkit)     ids_scan_rootkit    (cfg, rep);
    if (cfg->scan_persistence) ids_scan_persistence(cfg, rep);
    if (cfg->scan_processes)   ids_scan_processes  (cfg, rep, yara_rules);
    if (cfg->scan_memory)      ids_scan_memory     (cfg, rep, yara_rules);
    if (cfg->scan_network)     ids_scan_network    (cfg, rep);
    if (cfg->scan_events)      ids_scan_events     (cfg, rep);

    report_write(rep, cfg);
    report_free(rep);
    ids_config_free(cfg);
    return 0;
}