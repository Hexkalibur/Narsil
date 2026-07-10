/*
 * util.c -- Shared helpers for Narsil scan modules (v0.2).
 *
 * Before v0.2 the staging-path check, case-insensitive search, executable
 * path resolution and Authenticode verification were copy-pasted across
 * process.c, network.c, persistence.c and kernel.c. They now live here so a
 * fix (or a new staging directory) only has to be made once.
 *
 * This file also owns the suspicious command-line / script pattern table
 * used by both process.c (live command lines) and events.c (4688 records).
 */
#include "../include/ids.h"
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

/* -----------------------------------------------
   User-writable staging directories. Legitimate signed software very
   rarely executes from here; malware droppers almost always do.
   ----------------------------------------------- */
static const char *STAGING_DIRS[] = {
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\desktop\\", "\\public\\",
    "\\programdata\\", "\\$recycle.bin\\",
    "\\appdata\\roaming\\", "\\music\\", "\\pictures\\", "\\videos\\",
    NULL
};

/* Case-insensitive substring search (ASCII). Returns pointer into hay. */
const char *narsil_stristr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return NULL;
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n &&
               tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++; n++;
        }
        if (!*n) return hay;
    }
    return NULL;
}

/* Lowercase copy, always NUL-terminated, never overruns dst. */
void narsil_lower_copy(char *dst, const char *src, size_t dst_len) {
    if (dst_len == 0) return;
    size_t i = 0;
    for (; src && src[i] && i < dst_len - 1; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

BOOL narsil_is_staging_path(const char *path) {
    if (!path || !path[0]) return FALSE;
    char low[MAX_PATH];
    narsil_lower_copy(low, path, sizeof(low));
    for (int i = 0; STAGING_DIRS[i]; i++)
        if (strstr(low, STAGING_DIRS[i])) return TRUE;
    return FALSE;
}

void narsil_get_exe_path(DWORD pid, char *out, DWORD out_sz) {
    if (out_sz == 0) return;
    out[0] = '\0';
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return;
    DWORD sz = out_sz;
    QueryFullProcessImageNameA(hp, 0, out, &sz);
    CloseHandle(hp);
}

/* -----------------------------------------------
   Cross-process command-line retrieval.
   Toolhelp/NtQSI only give an image name, not the arguments an attacker
   actually cares about (encoded PowerShell, LOLBin flags, ...). This walks
   NtQueryInformationProcess -> PEB -> RTL_USER_PROCESS_PARAMETERS via
   ReadProcessMemory, which needs no COM/WMI dependency.
   64-bit target processes only: a 32-bit target under WOW64 has a second,
   32-bit PEB at a different address that this does not follow. Any failure
   (denied handle, WOW64 mismatch, exited process) yields an empty string,
   matching the "best effort" convention used by narsil_get_exe_path().
   ----------------------------------------------- */
typedef struct _NARSIL_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} NARSIL_PROCESS_BASIC_INFORMATION;

typedef LONG (WINAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

BOOL narsil_get_cmdline(DWORD pid, char *out, size_t out_len) {
    if (out_len == 0) return FALSE;
    out[0] = '\0';

    static PFN_NtQueryInformationProcess NtQIP = NULL;
    static BOOL tried = FALSE;
    if (!tried) {
        tried = TRUE;
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            NtQIP = (PFN_NtQueryInformationProcess)(void *)
                    GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
    if (!NtQIP) return FALSE;

    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, pid);
    if (!hp) return FALSE;

    NARSIL_PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret_len = 0;
    if (NtQIP(hp, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &ret_len) != 0
        || !pbi.PebBaseAddress) {
        CloseHandle(hp);
        return FALSE;
    }

    /* PEB->ProcessParameters is at offset 0x20 on 64-bit Windows. */
    PVOID proc_params = NULL;
    if (!ReadProcessMemory(hp, (BYTE *)pbi.PebBaseAddress + 0x20,
                           &proc_params, sizeof(proc_params), NULL) || !proc_params) {
        CloseHandle(hp);
        return FALSE;
    }

    /* RTL_USER_PROCESS_PARAMETERS->CommandLine (UNICODE_STRING) is at
       offset 0x70 on 64-bit Windows. */
    struct { USHORT Length; USHORT MaximumLength; PVOID Buffer; } cmdline_us = {0};
    if (!ReadProcessMemory(hp, (BYTE *)proc_params + 0x70,
                           &cmdline_us, sizeof(cmdline_us), NULL) ||
        !cmdline_us.Buffer || cmdline_us.Length == 0) {
        CloseHandle(hp);
        return FALSE;
    }

    WCHAR wbuf[1024] = {0};
    USHORT wlen = cmdline_us.Length;
    if (wlen >= sizeof(wbuf)) wlen = sizeof(wbuf) - sizeof(WCHAR);
    if (!ReadProcessMemory(hp, cmdline_us.Buffer, wbuf, wlen, NULL)) {
        CloseHandle(hp);
        return FALSE;
    }
    CloseHandle(hp);

    WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen / (int)sizeof(WCHAR),
                        out, (int)out_len - 1, NULL, NULL);
    return out[0] != '\0';
}

/* -----------------------------------------------
   Authenticode verification with catalog fallback + a small cache.
   Most inbox Windows binaries are catalog-signed (.cat), for which
   WinVerifyTrust alone returns TRUST_E_NOSIGNATURE; the catalog lookup is
   the authoritative second check.
   ----------------------------------------------- */
#define SIG_CACHE_CAP 1024
typedef struct { char path[MAX_PATH]; NarsilSig status; } SigCacheEntry;
static SigCacheEntry g_sig[SIG_CACHE_CAP];
static int           g_sig_n = 0;

static BOOL catalog_signed(const wchar_t *wpath) {
    HANDLE hFile = CreateFileW(wpath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HCATADMIN hAdmin = NULL;
    GUID action = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hAdmin, &action, 0)) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD hashLen = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0);

    BOOL found = FALSE;
    if (hashLen > 0) {
        BYTE *hash = (BYTE *)malloc(hashLen);
        if (hash) {
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0)) {
                HCATINFO hInfo = CryptCATAdminEnumCatalogFromHash(
                                     hAdmin, hash, hashLen, 0, NULL);
                if (hInfo) {
                    found = TRUE;
                    CryptCATAdminReleaseCatalogContext(hAdmin, hInfo, 0);
                }
            }
            free(hash);
        }
    }
    CloseHandle(hFile);
    CryptCATAdminReleaseContext(hAdmin, 0);
    return found;
}

NarsilSig narsil_sig_verify(const char *path) {
    if (!path || !path[0]) return NSIG_UNSIGNED;

    for (int i = 0; i < g_sig_n; i++)
        if (_stricmp(g_sig[i].path, path) == 0) return g_sig[i].status;

    wchar_t wp[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);

    WINTRUST_FILE_INFO fi; memset(&fi, 0, sizeof(fi));
    fi.cbStruct = sizeof(fi); fi.pcwszFilePath = wp;

    WINTRUST_DATA wd; memset(&wd, 0, sizeof(wd));
    wd.cbStruct            = sizeof(wd);
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG;

    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG rc   = WinVerifyTrust(NULL, &guid, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guid, &wd);

    NarsilSig s;
    if (rc == ERROR_SUCCESS)               s = NSIG_VALID;
    else if (rc == TRUST_E_NOSIGNATURE)    s = catalog_signed(wp) ? NSIG_VALID : NSIG_UNSIGNED;
    else                                   s = NSIG_INVALID;

    if (g_sig_n < SIG_CACHE_CAP) {
        strncpy(g_sig[g_sig_n].path, path, MAX_PATH - 1);
        g_sig[g_sig_n].status = s;
        g_sig_n++;
    }
    return s;
}

const char *narsil_sig_str(NarsilSig s) {
    switch (s) {
        case NSIG_VALID:    return "signed";
        case NSIG_UNSIGNED: return "unsigned";
        default:            return "tampered";
    }
}

/* -----------------------------------------------
   Suspicious command-line / script pattern table.
   Ordered most-specific first; narsil_match_pattern returns the first hit
   so a strong indicator (encoded PowerShell) wins over a weak one.
   ----------------------------------------------- */
static const NarsilPattern PATTERNS[] = {
    /* --- PowerShell abuse (T1059.001 / T1027) --- */
    { "-encodedcommand",        SEV_HIGH,     "T1027",     "encoded PowerShell command" },
    { "-enc ",                  SEV_HIGH,     "T1027",     "encoded PowerShell command" },
    { "-e jab",                 SEV_HIGH,     "T1027",     "base64 PowerShell (JAB...)" },
    { "frombase64string",       SEV_HIGH,     "T1140",     "inline base64 decode" },
    { "-nop ",                  SEV_MEDIUM,   "T1059.001", "PowerShell -NoProfile" },
    { "-noprofile",             SEV_MEDIUM,   "T1059.001", "PowerShell -NoProfile" },
    { "-windowstyle hidden",    SEV_HIGH,     "T1564.003", "hidden window" },
    { "-w hidden",              SEV_HIGH,     "T1564.003", "hidden window" },
    { "iex(",                   SEV_HIGH,     "T1059.001", "Invoke-Expression" },
    { "invoke-expression",      SEV_HIGH,     "T1059.001", "Invoke-Expression" },
    { "downloadstring",         SEV_HIGH,     "T1105",     "in-memory download cradle" },
    { "downloadfile",           SEV_MEDIUM,   "T1105",     "remote file download" },
    { "invoke-webrequest",      SEV_MEDIUM,   "T1105",     "remote download cradle" },
    { "net.webclient",          SEV_HIGH,     "T1105",     "WebClient download cradle" },
    { "bypass",                 SEV_MEDIUM,   "T1059.001", "execution-policy bypass" },
    { "-executionpolicy",       SEV_MEDIUM,   "T1059.001", "execution-policy override" },
    { "hidden -e",              SEV_HIGH,     "T1027",     "hidden encoded command" },
    /* --- LOLBins (T1218) --- */
    { "mshta ",                 SEV_HIGH,     "T1218.005", "mshta script execution" },
    { "regsvr32 ",              SEV_MEDIUM,   "T1218.010", "regsvr32 proxy execution" },
    { "scrobj.dll",             SEV_HIGH,     "T1218.010", "regsvr32 scriptlet (squiblydoo)" },
    { "rundll32 ",              SEV_MEDIUM,   "T1218.011", "rundll32 proxy execution" },
    { "javascript:",            SEV_HIGH,     "T1218.011", "rundll32 javascript" },
    { "certutil ",              SEV_MEDIUM,   "T1105",     "certutil download/decode" },
    { "-decode",                SEV_HIGH,     "T1140",     "certutil -decode" },
    { "-urlcache",              SEV_HIGH,     "T1105",     "certutil -urlcache download" },
    { "bitsadmin ",             SEV_MEDIUM,   "T1197",     "BITS job abuse" },
    { "/transfer",              SEV_MEDIUM,   "T1197",     "BITS transfer" },
    { "wmic ",                  SEV_MEDIUM,   "T1047",     "WMI command execution" },
    { "process call create",    SEV_HIGH,     "T1047",     "WMI process create" },
    { "msiexec ",               SEV_LOW,      "T1218.007", "msiexec execution" },
    { "installutil",            SEV_MEDIUM,   "T1218.004", "InstallUtil proxy execution" },
    { "regasm",                 SEV_MEDIUM,   "T1218.009", "Regasm proxy execution" },
    { "regsvcs",                SEV_MEDIUM,   "T1218.009", "Regsvcs proxy execution" },
    /* --- Defense evasion / recon (T1562 / T1490) --- */
    { "vssadmin delete",        SEV_CRITICAL, "T1490",     "shadow-copy deletion (ransomware)" },
    { "wbadmin delete",         SEV_CRITICAL, "T1490",     "backup deletion (ransomware)" },
    { "bcdedit",                SEV_HIGH,     "T1490",     "boot-config tampering" },
    { "recoveryenabled no",     SEV_CRITICAL, "T1490",     "recovery disabled (ransomware)" },
    { "cipher /w",              SEV_HIGH,     "T1485",     "secure data wipe" },
    { "set-mppreference",       SEV_HIGH,     "T1562.001", "Defender tampering" },
    { "add-mppreference",       SEV_HIGH,     "T1562.001", "Defender exclusion" },
    { "disablerealtimemonitoring", SEV_CRITICAL, "T1562.001", "Defender realtime disabled" },
    { "netsh advfirewall",      SEV_MEDIUM,   "T1562.004", "firewall tampering" },
    { "wevtutil cl",            SEV_CRITICAL, "T1070.001", "event log cleared" },
    { "clear-eventlog",         SEV_CRITICAL, "T1070.001", "event log cleared" },
    { "fsutil usn deletejournal", SEV_HIGH,   "T1070",     "USN journal deletion" },
    { "attrib +h +s",           SEV_MEDIUM,   "T1564.001", "hiding files" },
    /* --- Credential access / lateral (T1003 / T1021) --- */
    { "sekurlsa",               SEV_CRITICAL, "T1003.001", "Mimikatz lsass dump" },
    { "lsadump",                SEV_CRITICAL, "T1003",     "Mimikatz LSA dump" },
    { "comsvcs.dll",            SEV_HIGH,     "T1003.001", "MiniDump comsvcs lsass" },
    { "minidump",               SEV_HIGH,     "T1003.001", "process memory dump" },
    { "ntds.dit",               SEV_CRITICAL, "T1003.003", "NTDS credential theft" },
    { "\\\\admin$",             SEV_HIGH,     "T1021.002", "admin share lateral movement" },
    { "psexec",                 SEV_HIGH,     "T1569.002", "PsExec service execution" },
    { "reg save hklm\\sam",     SEV_CRITICAL, "T1003.002", "SAM hive dump" },
    { "whoami /priv",           SEV_LOW,      "T1033",     "privilege enumeration" },
    { NULL, 0, NULL, NULL }
};

const NarsilPattern *narsil_match_pattern(const char *text) {
    if (!text || !text[0]) return NULL;
    char low[1024];
    narsil_lower_copy(low, text, sizeof(low));
    for (int i = 0; PATTERNS[i].pattern; i++)
        if (strstr(low, PATTERNS[i].pattern)) return &PATTERNS[i];
    return NULL;
}

/* -----------------------------------------------
   Blocked-IP matching: exact string list (legacy) + CIDR ranges (v0.2).
   ----------------------------------------------- */
BOOL narsil_ip_blocked(IdsConfig *cfg, const char *ip) {
    if (!ip || !ip[0]) return FALSE;

    for (int i = 0; i < cfg->blocked_ip_count; i++)
        if (strcmp(cfg->blocked_ips[i], ip) == 0) return TRUE;

    if (cfg->blocked_net_count > 0) {
        DWORD addr = inet_addr(ip);
        if (addr != INADDR_NONE) {
            for (int i = 0; i < cfg->blocked_net_count; i++)
                if ((addr & cfg->blocked_nets[i].mask) == cfg->blocked_nets[i].net)
                    return TRUE;
        }
    }
    return FALSE;
}
