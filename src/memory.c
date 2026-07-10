/*
 * memory.c -- Process memory anomaly scanner (SCAN only).  v0.2
 *
 * v0.1 flagged every process with a single private RWX region as HIGH.
 * On a normal desktop that is a flood of false positives: browsers (JIT),
 * .NET runtimes, Defender's AMSI host and dozens of backgroundTaskHost
 * instances all legitimately allocate RWX. The v0.1 report was 79 HIGH
 * alerts, essentially none of them real.
 *
 * v0.2 keeps VirtualQueryEx region walking but adds evidence-based triage
 * so severity reflects how injection-like a region actually is:
 *
 *   1. Content inspection -- private executable regions are read with
 *      ReadProcessMemory and checked for a mapped PE image (MZ / PE magic).
 *      A manually mapped module in private memory is a near-certain
 *      reflective-injection footprint  ->  ALERT_INJECTED_PE (CRITICAL).
 *
 *   2. Thread-start correlation -- every thread's Win32 start address is
 *      resolved (NtQueryInformationThread) and tested against the private
 *      executable regions. A thread whose entry point lives in private,
 *      non-image memory is the footprint of CreateRemoteThread shellcode
 *      ->  ALERT_INJECTED_THREAD (CRITICAL).
 *
 *   3. Scoring -- regions that are merely RWX (no PE header, no thread
 *      entry) are scored on size and count. Known JIT / .NET hosts
 *      (allow_rwx list, seeded with common ones) are treated as evidence,
 *      not alerts. Everything else becomes a single MEDIUM alert per
 *      process instead of one HIGH per region.
 *
 * memory_strict in the config restores the noisy v0.1 behavior (one HIGH
 * per RWX region) for analysts who want the raw firehose.
 *
 * Alert types: ALERT_MEMORY_ANOMALY / ALERT_INJECTED_PE / ALERT_INJECTED_THREAD
 * MITRE: T1055 (.001 reflective, .002 hollowing, .003 remote thread)
 */
#include "../include/ids.h"
#include "../include/report.h"

#define MAX_REGIONS_PER_PROC 131072
#define MAX_THREAD_STARTS    4096

/* Processes that legitimately fill memory with RWX/JIT pages. RWX-only
   findings in these are recorded as evidence, not raised as alerts, unless
   content inspection finds a mapped PE or a thread entry in private code. */
static const char *DEFAULT_JIT[] = {
    "firefox.exe", "chrome.exe", "msedge.exe", "msedgewebview2.exe",
    "brave.exe", "opera.exe", "iexplore.exe", "chromium.exe",
    "java.exe", "javaw.exe", "javaws.exe", "node.exe",
    "devenv.exe", "code.exe", "python.exe", "python3.exe",
    "MsMpEng.exe", "NisSrv.exe",
    "dotnet.exe", "powershell.exe", "pwsh.exe",
    "WhatsApp.exe", "WhatsApp.Root.exe", "Discord.exe", "Spotify.exe",
    "PhoneExperienceHost.exe", "eve-online.exe",
    NULL
};

/* NtQueryInformationThread -- resolve a thread's Win32 start address.
   ntdll is not in the import libs, so bind at runtime. */
#ifndef ThreadQuerySetWin32StartAddress
#  define ThreadQuerySetWin32StartAddress 9
#endif
typedef LONG (WINAPI *PFN_NtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_NtQueryInformationThread g_NtQIT = NULL;

static void resolve_ntqit(void) {
    static BOOL tried = FALSE;
    if (tried) return;
    tried = TRUE;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        g_NtQIT = (PFN_NtQueryInformationThread)(void *)
                  GetProcAddress(ntdll, "NtQueryInformationThread");
}

/* Collect the Win32 start addresses of every thread in pid. */
static int collect_thread_starts(DWORD pid, ULONG_PTR *out, int cap) {
    resolve_ntqit();
    if (!g_NtQIT) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te; memset(&te, 0, sizeof(te)); te.dwSize = sizeof(te);
    int n = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (n >= cap) break;
            HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                                   te.th32ThreadID);
            if (!ht) continue;
            ULONG_PTR start = 0;
            if (g_NtQIT(ht, ThreadQuerySetWin32StartAddress,
                        &start, sizeof(start), NULL) == 0 && start)
                out[n++] = start;
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

static BOOL prot_is_exec(DWORD prot) {
    DWORD base = prot & 0xFF;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static BOOL prot_is_wx(DWORD prot) {
    DWORD base = prot & 0xFF;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static BOOL is_jit_process(IdsConfig *cfg, const char *name) {
    for (int i = 0; DEFAULT_JIT[i]; i++)
        if (_stricmp(name, DEFAULT_JIT[i]) == 0) return TRUE;
    for (int i = 0; i < cfg->allow_rwx_count; i++)
        if (_stricmp(name, cfg->allow_rwx[i]) == 0) return TRUE;
    return FALSE;
}

/* Does a mapped PE image start at base? Reads the first bytes and checks
   the MZ magic plus the e_lfanew-referenced PE signature. */
static BOOL region_has_pe(HANDLE hp, unsigned char *base, SIZE_T region_size) {
    unsigned char hdr[0x40];
    if (region_size < sizeof(hdr)) return FALSE;
    SIZE_T got = 0;
    if (!ReadProcessMemory(hp, base, hdr, sizeof(hdr), &got) || got < sizeof(hdr))
        return FALSE;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return FALSE;

    LONG e_lfanew = *(LONG *)(hdr + 0x3C);
    if (e_lfanew <= 0 || (SIZE_T)e_lfanew + 4 > region_size) return FALSE;

    unsigned char sig[4];
    if (!ReadProcessMemory(hp, base + e_lfanew, sig, 4, &got) || got < 4)
        return FALSE;
    return sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0;
}

/* Per-process accumulation of what the region walk found. */
typedef struct {
    int   rwx;              /* count of RWX (W^X-violating) regions   */
    int   priv_exec;        /* count of private executable regions    */
    ULONG_PTR first_hit;    /* base of first suspicious region        */
    SIZE_T largest;         /* largest private-exec region size       */
    BOOL  pe_found;         /* mapped PE image in private memory      */
    ULONG_PTR pe_addr;
    BOOL  thread_in_priv;   /* a thread starts inside private code    */
    ULONG_PTR thread_addr;
} MemFindings;

/* Scan one process's address space (hp already opened by the caller).
   Fills *mf with what was found. */
static void scan_process_memory(DWORD pid, HANDLE hp, MemFindings *mf) {
    memset(mf, 0, sizeof(*mf));

    ULONG_PTR starts[MAX_THREAD_STARTS];
    int n_starts = collect_thread_starts(pid, starts, MAX_THREAD_STARTS);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = 0;
    int regions = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (++regions > MAX_REGIONS_PER_PROC) break;

        unsigned char *next = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr && mbi.RegionSize != 0) break;

        BOOL committed_priv_exec = (mbi.State == MEM_COMMIT &&
                                    mbi.Type  == MEM_PRIVATE &&
                                    prot_is_exec(mbi.Protect));

        if (committed_priv_exec) {
            if (mf->priv_exec == 0)
                mf->first_hit = (ULONG_PTR)mbi.BaseAddress;
            mf->priv_exec++;
            if (mbi.RegionSize > mf->largest) mf->largest = mbi.RegionSize;

            if (prot_is_wx(mbi.Protect)) mf->rwx++;

            if (!mf->pe_found &&
                region_has_pe(hp, (unsigned char *)mbi.BaseAddress, mbi.RegionSize)) {
                mf->pe_found = TRUE;
                mf->pe_addr  = (ULONG_PTR)mbi.BaseAddress;
            }

            if (!mf->thread_in_priv) {
                ULONG_PTR base = (ULONG_PTR)mbi.BaseAddress;
                ULONG_PTR end  = base + mbi.RegionSize;
                for (int i = 0; i < n_starts; i++) {
                    if (starts[i] >= base && starts[i] < end) {
                        mf->thread_in_priv = TRUE;
                        mf->thread_addr    = starts[i];
                        break;
                    }
                }
            }
        }

        if (next <= addr) break;
        addr = next;
    }
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_memory(IdsConfig *cfg, ScanReport *rep, const char *yara_rules) {
    (void)yara_rules;   /* YARA matching not yet implemented */
    LOG_INFO("scan: process memory (RWX / injection triage)...");

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

            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE, pid);
            if (!hp) hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                      FALSE, pid);
            if (!hp) { denied++; continue; }

            MemFindings mf;
            scan_process_memory(pid, hp, &mf);
            scanned++;

            if (mf.priv_exec == 0) { CloseHandle(hp); continue; }

            char exe_path[MAX_PATH] = {0};
            narsil_get_exe_path(pid, exe_path, MAX_PATH);
            CloseHandle(hp);

            BOOL jit = is_jit_process(cfg, pe.szExeFile);

            /* Strict mode: reproduce v0.1 -- one HIGH per RWX-bearing process.
               Gated on mf.rwx (not mf.priv_exec): v0.1 only ever looked at
               W^X pages, so a process with merely private EXECUTE_READ
               regions and no RWX must not produce a "0 RWX region(s)" alert. */
            if (cfg->memory_strict && mf.rwx > 0) {
                Alert a = {0};
                a.type      = ALERT_MEMORY_ANOMALY;
                a.severity  = SEV_HIGH;
                a.timestamp = time(NULL);
                a.pid       = pid;
                strncpy(a.process_name, pe.szExeFile, MAX_PATH - 1);
                if (exe_path[0]) strncpy(a.file_path, exe_path, MAX_PATH - 1);
                strncpy(a.technique_id, "T1055", sizeof(a.technique_id) - 1);
                snprintf(a.description, MAX_DESCRIPTION,
                         "%d private RWX region(s) in %s (pid=%lu), first @ 0x%llx",
                         mf.rwx, pe.szExeFile, pid, (unsigned long long)mf.first_hit);
                report_add(rep, &a);
                ids_log_alert(cfg, &a);
                flagged++;
            }

            /* Tier 1 -- mapped PE image in private memory: near-certain
               reflective injection, regardless of process identity. */
            if (mf.pe_found) {
                Alert a = {0};
                a.type      = ALERT_INJECTED_PE;
                a.severity  = SEV_CRITICAL;
                a.timestamp = time(NULL);
                a.pid       = pid;
                strncpy(a.process_name, pe.szExeFile, MAX_PATH - 1);
                if (exe_path[0]) strncpy(a.file_path, exe_path, MAX_PATH - 1);
                strncpy(a.technique_id, "T1055.001", sizeof(a.technique_id) - 1);
                snprintf(a.description, MAX_DESCRIPTION,
                         "Mapped PE image in private memory of %s (pid=%lu) @ 0x%llx "
                         "-- reflective DLL / process injection",
                         pe.szExeFile, pid, (unsigned long long)mf.pe_addr);
                report_add(rep, &a);
                ids_log_alert(cfg, &a);
                if (tbl) report_table_add(tbl, exe_path, pe.szExeFile,
                                          "mapped PE in private memory",
                                          ENTRY_FLAGGED, a.description);
                flagged++;
            }

            /* Tier 2 -- thread entry point inside private executable memory:
               classic CreateRemoteThread / QueueUserAPC shellcode marker. */
            if (mf.thread_in_priv) {
                Alert a = {0};
                a.type      = ALERT_INJECTED_THREAD;
                a.severity  = SEV_CRITICAL;
                a.timestamp = time(NULL);
                a.pid       = pid;
                strncpy(a.process_name, pe.szExeFile, MAX_PATH - 1);
                if (exe_path[0]) strncpy(a.file_path, exe_path, MAX_PATH - 1);
                strncpy(a.technique_id, "T1055.003", sizeof(a.technique_id) - 1);
                snprintf(a.description, MAX_DESCRIPTION,
                         "Thread start address 0x%llx in private executable memory of "
                         "%s (pid=%lu) -- possible remote-thread injection",
                         (unsigned long long)mf.thread_addr, pe.szExeFile, pid);
                report_add(rep, &a);
                ids_log_alert(cfg, &a);
                if (tbl) report_table_add(tbl, exe_path, pe.szExeFile,
                                          "thread entry in private memory",
                                          ENTRY_FLAGGED, a.description);
                flagged++;
            }

            /* Tier 3 -- plain RWX with no PE / thread evidence. JIT hosts
               are recorded as evidence only; everything else gets a single
               MEDIUM summary alert instead of one HIGH per region. */
            if (!mf.pe_found && !mf.thread_in_priv && mf.rwx > 0 && !cfg->memory_strict) {
                char detail[128];
                snprintf(detail, sizeof(detail),
                         "%d RWX region(s), largest %zu KB, first @ 0x%llx",
                         mf.rwx, (size_t)(mf.largest / 1024),
                         (unsigned long long)mf.first_hit);

                if (jit) {
                    if (tbl) report_table_add(tbl, exe_path, pe.szExeFile, detail,
                                              ENTRY_OK, "known JIT/CLR host");
                } else {
                    Alert a = {0};
                    a.type      = ALERT_MEMORY_ANOMALY;
                    a.severity  = SEV_MEDIUM;
                    a.timestamp = time(NULL);
                    a.pid       = pid;
                    strncpy(a.process_name, pe.szExeFile, MAX_PATH - 1);
                    if (exe_path[0]) strncpy(a.file_path, exe_path, MAX_PATH - 1);
                    strncpy(a.technique_id, "T1055", sizeof(a.technique_id) - 1);
                    snprintf(a.description, MAX_DESCRIPTION,
                             "%s (pid=%lu): %s -- no mapped PE or thread evidence, "
                             "unclassified private RWX",
                             pe.szExeFile, pid, detail);
                    report_add(rep, &a);
                    ids_log_alert(cfg, &a);
                    if (tbl) report_table_add(tbl, exe_path, pe.szExeFile, detail,
                                              ENTRY_WARN, "unclassified RWX, no PE/thread evidence");
                    flagged++;
                }
            }

        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    if (tbl && flagged == 0)
        report_table_add(tbl, "", "memory", "RWX / injection triage",
                         ENTRY_OK, "no injected-code footprint found");

    LOG_INFO("scan: memory -- done  total=%d  scanned=%d  denied=%d  flagged=%d",
             total, scanned, denied, flagged);
}

