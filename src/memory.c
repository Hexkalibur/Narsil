/*
 * memory.c -- Process memory anomaly scanner (SCAN only).
 *
 * Walks every accessible process's address space with VirtualQueryEx and
 * flags regions whose protection + type combination is a strong indicator
 * of code injection or shellcode staging:
 *
 *   - MEM_PRIVATE + committed + executable-and-writable (RWX / WCX)
 *       Private (not image-backed) pages that are both writable and
 *       executable are the canonical footprint of injected shellcode.
 *       Legitimate code lives in MEM_IMAGE pages and is rarely writable.
 *
 * VirtualQueryEx only reads region metadata, never process memory, so no
 * structured-exception handling is required. Requires SeDebugPrivilege
 * (enabled in main.c) to open protected processes.
 *
 * Alert type: ALERT_MEMORY_ANOMALY   MITRE: T1055
 *
 * yara_rules is accepted for interface parity with the other scanners;
 * YARA content matching is not yet wired in.
 */
#include "../include/ids.h"
#include "../include/report.h"

/* Upper bound on regions walked per process (defensive against a
   pathological VAD tree). 128k regions * 4KB is already a 512MB+ map. */
#define MAX_REGIONS_PER_PROC 131072

static BOOL prot_is_wx(DWORD prot) {
    /* Mask off guard/nocache/writecombine modifier bits first. */
    DWORD base = prot & 0xFF;
    return base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

/* Scan one process. Returns number of suspicious regions (or -1 if the
   process could not be opened). */
static int scan_process_memory(DWORD pid, const char *name,
                               IdsConfig *cfg, ScanReport *rep,
                               EvidenceTable *tbl) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) {
        /* PROCESS_QUERY_INFORMATION may be denied; fall back to limited. */
        hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hp) return -1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = 0;
    int suspicious = 0;
    unsigned long long first_hit = 0;
    int regions = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (++regions > MAX_REGIONS_PER_PROC) break;

        if (mbi.State == MEM_COMMIT &&
            mbi.Type  == MEM_PRIVATE &&
            prot_is_wx(mbi.Protect)) {
            if (suspicious == 0)
                first_hit = (unsigned long long)(ULONG_PTR)mbi.BaseAddress;
            suspicious++;
        }

        unsigned char *next = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;   /* guard against wrap / zero region */
        addr = next;
    }

    CloseHandle(hp);

    if (suspicious > 0) {
        char exe_path[MAX_PATH] = {0};
        HANDLE h2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h2) {
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameA(h2, 0, exe_path, &sz);
            CloseHandle(h2);
        }

        Alert a = {0};
        a.type      = ALERT_MEMORY_ANOMALY;
        a.severity  = SEV_HIGH;
        a.timestamp = time(NULL);
        a.pid       = pid;
        strncpy(a.process_name, name, MAX_PATH - 1);
        if (exe_path[0]) strncpy(a.file_path, exe_path, MAX_PATH - 1);
        strncpy(a.technique_id, "T1055", sizeof(a.technique_id) - 1);
        snprintf(a.description, MAX_DESCRIPTION,
                 "%d private RWX region(s) in %s (pid=%lu), first @ 0x%llx "
                 "-- possible injected code",
                 suspicious, name, pid, first_hit);

        report_add(rep, &a);
        ids_log_alert(cfg, &a);

        char detail[96];
        snprintf(detail, sizeof(detail), "%d RWX region(s) @ 0x%llx",
                 suspicious, first_hit);
        if (tbl) report_table_add(tbl, exe_path, name, detail, ENTRY_FLAGGED,
                                  "private executable+writable memory");
    }
    return suspicious;
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_memory(IdsConfig *cfg, ScanReport *rep, const char *yara_rules) {
    (void)yara_rules;   /* YARA matching not yet implemented */
    LOG_INFO("scan: process memory (RWX private regions)...");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_ERR("memory: snapshot failed: %s", buf);
        return;
    }

    EvidenceTable *tbl = report_table_begin(rep, "memory");

    PROCESSENTRY32 pe; memset(&pe, 0, sizeof(pe)); pe.dwSize = sizeof(pe);
    int total = 0, scanned = 0, flagged = 0, denied = 0;

    if (Process32First(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4) continue;   /* Idle / System */
            total++;

            int r = scan_process_memory(pid, pe.szExeFile, cfg, rep, tbl);
            if (r < 0) { denied++; continue; }
            scanned++;
            if (r > 0) flagged++;
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    if (tbl && flagged == 0)
        report_table_add(tbl, "", "memory", "RWX private-region scan",
                         ENTRY_OK, "no injected-code footprint found");

    LOG_INFO("scan: memory -- done  total=%d  scanned=%d  denied=%d  flagged=%d",
             total, scanned, denied, flagged);
}
