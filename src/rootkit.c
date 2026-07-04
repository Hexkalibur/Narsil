/*
 * rootkit.c -- Hidden process detection (SCAN only).
 *
 * Cross-references two independent process enumeration sources:
 *
 *   1. CreateToolhelp32Snapshot  -- user-mode API, walks a snapshot that
 *      user-mode rootkits commonly hook or unlink from.
 *   2. NtQuerySystemInformation(SystemProcessInformation) -- the syscall
 *      that feeds Task Manager; closer to the kernel and harder to tamper
 *      with from user land.
 *
 * A PID visible to NtQSI but absent from Toolhelp is a classic sign of a
 * process hiding itself (API hooking / DKOM unlinking).
 *
 * We treat NtQSI as the more authoritative source. To avoid false
 * positives from processes that legitimately start or exit between the two
 * enumerations, a discrepancy is confirmed with a direct OpenProcess probe
 * before it is reported.
 *
 * Alert type: ALERT_HIDDEN_PROCESS   MITRE: T1014 / T1055
 */
#include "../include/ids.h"
#include "../include/report.h"

/* -----------------------------------------------
   NtQuerySystemInformation plumbing
   (ntdll is not in the SDK import libs, so bind at runtime)
   ----------------------------------------------- */
#ifndef STATUS_INFO_LENGTH_MISMATCH
#  define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif

#define SYSTEM_PROCESS_INFORMATION_CLASS 5

typedef struct _NARSIL_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NARSIL_UNICODE_STRING;

/* Partial layout of SYSTEM_PROCESS_INFORMATION -- only the leading fields
   we need. The real struct is larger; NextEntryOffset lets us skip the
   remainder safely. */
typedef struct _NARSIL_SYSTEM_PROCESS_INFORMATION {
    ULONG                 NextEntryOffset;
    ULONG                 NumberOfThreads;
    LARGE_INTEGER         Reserved1[3];
    LARGE_INTEGER         CreateTime;
    LARGE_INTEGER         UserTime;
    LARGE_INTEGER         KernelTime;
    NARSIL_UNICODE_STRING ImageName;
    LONG                  BasePriority;
    HANDLE                UniqueProcessId;
    HANDLE                InheritedFromUniqueProcessId;
} NARSIL_SYSTEM_PROCESS_INFORMATION;

typedef LONG (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

/* -----------------------------------------------
   PID set helpers (flat sorted-free arrays, small N)
   ----------------------------------------------- */
#define MAX_PIDS 4096
typedef struct { DWORD pids[MAX_PIDS]; int n; } PidSet;

static void pidset_add(PidSet *s, DWORD pid) {
    if (s->n < MAX_PIDS) s->pids[s->n++] = pid;
}

static BOOL pidset_has(const PidSet *s, DWORD pid) {
    for (int i = 0; i < s->n; i++)
        if (s->pids[i] == pid) return TRUE;
    return FALSE;
}

/* -----------------------------------------------
   Toolhelp enumeration
   ----------------------------------------------- */
static void enum_toolhelp(PidSet *out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("rootkit: Toolhelp snapshot failed: %s", buf);
        return;
    }
    PROCESSENTRY32 pe; memset(&pe, 0, sizeof(pe)); pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do { pidset_add(out, pe.th32ProcessID); }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    LOG_DBG("rootkit: Toolhelp reported %d processes", out->n);
}

/* -----------------------------------------------
   NtQSI enumeration. Returns the raw buffer via *outbuf so the caller
   can also read image names; caller frees it.
   ----------------------------------------------- */
static BYTE *enum_ntqsi(PFN_NtQuerySystemInformation fn, PidSet *out) {
    ULONG len = 0x10000;
    BYTE *buf = NULL;
    LONG  st;

    for (int attempt = 0; attempt < 6; attempt++) {
        BYTE *nb = (BYTE *)realloc(buf, len);
        if (!nb) { free(buf); LOG_WARN("rootkit: NtQSI OOM"); return NULL; }
        buf = nb;

        ULONG ret = 0;
        st = fn(SYSTEM_PROCESS_INFORMATION_CLASS, buf, len, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            len = (ret > len) ? ret + 0x4000 : len * 2;
            continue;
        }
        break;
    }

    if (st < 0) {
        LOG_WARN("rootkit: NtQuerySystemInformation failed (status=0x%lx)",
                 (unsigned long)st);
        free(buf);
        return NULL;
    }

    const BYTE *p = buf;
    for (;;) {
        const NARSIL_SYSTEM_PROCESS_INFORMATION *spi =
            (const NARSIL_SYSTEM_PROCESS_INFORMATION *)p;
        pidset_add(out, (DWORD)(ULONG_PTR)spi->UniqueProcessId);
        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
    LOG_DBG("rootkit: NtQSI reported %d processes", out->n);
    return buf;
}

/* Resolve a PID's image name from the NtQSI buffer (best effort). */
static void ntqsi_image_name(const BYTE *buf, DWORD pid,
                             char *out, size_t out_len) {
    out[0] = '\0';
    if (!buf) return;
    const BYTE *p = buf;
    for (;;) {
        const NARSIL_SYSTEM_PROCESS_INFORMATION *spi =
            (const NARSIL_SYSTEM_PROCESS_INFORMATION *)p;
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) {
            if (spi->ImageName.Buffer && spi->ImageName.Length)
                WideCharToMultiByte(CP_UTF8, 0, spi->ImageName.Buffer,
                                    spi->ImageName.Length / (int)sizeof(WCHAR),
                                    out, (int)out_len - 1, NULL, NULL);
            return;
        }
        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
}

/* Confirm a process really exists by opening it directly. This filters
   out entries that exited during the (tiny) window between enumerations. */
static BOOL process_alive(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) { CloseHandle(h); return TRUE; }
    /* ERROR_ACCESS_DENIED means it exists but we can't open it -> alive. */
    return GetLastError() == ERROR_ACCESS_DENIED;
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_rootkit(IdsConfig *cfg, ScanReport *rep) {
    LOG_INFO("scan: rootkit / hidden processes...");

    EvidenceTable *tbl = report_table_begin(rep, "hidden_processes");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PFN_NtQuerySystemInformation NtQSI = ntdll
        ? (PFN_NtQuerySystemInformation)(void *)
              GetProcAddress(ntdll, "NtQuerySystemInformation")
        : NULL;
    if (!NtQSI) {
        LOG_WARN("rootkit: NtQuerySystemInformation unavailable -- skipping");
        if (tbl) report_table_add(tbl, "", "ntdll", "NtQSI unavailable",
                                  ENTRY_SKIPPED, "cannot cross-reference");
        return;
    }

    PidSet toolhelp = { .n = 0 };
    PidSet ntqsi    = { .n = 0 };

    enum_toolhelp(&toolhelp);
    BYTE *ntbuf = enum_ntqsi(NtQSI, &ntqsi);
    if (!ntbuf) {
        LOG_WARN("rootkit: NtQSI enumeration failed -- skipping");
        return;
    }

    int flagged = 0;
    for (int i = 0; i < ntqsi.n; i++) {
        DWORD pid = ntqsi.pids[i];
        if (pid == 0) continue;                 /* System Idle */
        if (pidset_has(&toolhelp, pid)) continue;

        /* Present in kernel view, absent from Toolhelp. Confirm liveness
           to rule out a start/exit race before crying rootkit. */
        if (!process_alive(pid)) continue;

        char name[MAX_PATH] = {0};
        ntqsi_image_name(ntbuf, pid, name, sizeof(name));
        const char *disp = name[0] ? name : "<unknown>";

        Alert a = {0};
        a.type      = ALERT_HIDDEN_PROCESS;
        a.severity  = SEV_CRITICAL;
        a.timestamp = time(NULL);
        a.pid       = pid;
        strncpy(a.process_name, disp, MAX_PATH - 1);
        strncpy(a.technique_id, "T1014", sizeof(a.technique_id) - 1);
        snprintf(a.description, MAX_DESCRIPTION,
                 "Hidden process pid=%lu (%s): visible to NtQSI but not "
                 "Toolhelp -- possible rootkit unlinking",
                 pid, disp);

        report_add(rep, &a);
        ids_log_alert(cfg, &a);

        char detail[64];
        snprintf(detail, sizeof(detail), "pid=%lu NtQSI-only", pid);
        if (tbl) report_table_add(tbl, name, disp, detail, ENTRY_FLAGGED,
                                  "present in kernel view, hidden from Toolhelp");
        flagged++;
    }

    if (tbl && flagged == 0)
        report_table_add(tbl, "", "cross-reference", "Toolhelp vs NtQSI",
                         ENTRY_OK, "no hidden processes detected");

    free(ntbuf);
    LOG_INFO("scan: rootkit -- done  toolhelp=%d  ntqsi=%d  hidden=%d",
             toolhelp.n, ntqsi.n, flagged);
}
