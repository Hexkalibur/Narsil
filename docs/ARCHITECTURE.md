# Narsil — Architecture & Roadmap

## Vision
Personal security monitor for cyber sec professionals and power users.
Answers the question: "Is my machine compromised right now?"
Two modes: `scan` (deep one-shot analysis) and `live` (real-time monitoring).
Native Windows APIs only. No heavy external dependencies. Minimal footprint.

---

## Current State (DONE)

| Module | File | Status |
|--------|------|--------|
| Config parser | config.c | done — SRWLOCK, SecureZeroMemory |
| Alert dispatch | alert.c | done — JSONL output, json_escape |
| Report engine | report.c | done — .md + .jsonl, ASCII only |
| Network monitor (live) | network.c | done — TCP/UDP, port scan, staging path |
| Process monitor (live) | process.c | done — name/sig/staging tier detection |
| Event log monitor (live) | events.c | done — XML parser fixed, enriched alerts |
| Lifecycle / CLI | main.c | done — scan/live split, is_elevated, graceful shutdown |
| Header | ids.h | done — SRWLOCK, SAFE_COPY, extern shutdown event |

---

## Module Roadmap

### Phase 1 — Scan Mode Foundation (immediate)

#### 1a. SeDebugPrivilege (main.c)
Enable at startup via AdjustTokenPrivileges.
Required by: memory.c, credential.c, stealth.c.
Log warning if not obtainable (domain policy may block).

#### 1b. kernel.c — Driver Enumeration (SCAN only)
- EnumDeviceDrivers + GetDeviceDriverFileName
- WinVerifyTrust on every driver .sys file
- Flag: unsigned driver, anonymous driver (no file on disk), driver in user-writable path
- Alert type: ALERT_SUSPICIOUS_DRIVER (new)

#### 1c. rootkit.c — Hidden Process Detection (SCAN only)
- Enumerate via CreateToolhelp32Snapshot (user-mode linked list)
- Enumerate via NtQuerySystemInformation(SystemProcessInformation) (kernel array)
- Cross-reference: PID in NtQSI but not in Toolhelp = DKOM hidden process
- Alert type: ALERT_HIDDEN_PROCESS (new)

#### 1d. persistence.c — Persistence Mechanism Scanner (SCAN only)
Registry Run keys:
  HKLM/HKCU SOFTWARE\Microsoft\Windows\CurrentVersion\Run[Once]
  HKLM SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\{Userinit,Shell}
Services: EnumServicesStatusEx — flag unsigned binaries, user-writable paths
Scheduled Tasks: parse %SystemRoot%\System32\Tasks\ XML files
WMI subscriptions: query root\subscription for __EventFilter + consumers
COM hijacking: HKCU\Software\Classes\CLSID\*\InprocServer32 shadowing system CLSIDs
Alert type: ALERT_PERSISTENCE (new)

#### 1e. memory.c — Process Memory Inspection (SCAN only)
Requires SeDebugPrivilege. All calls wrapped in __try/__except.
- VirtualQueryEx on all processes — find MEM_COMMIT + MEM_PRIVATE + EXECUTE regions (shellcode)
- PEB ImageBaseAddress vs thread start address cross-check (hollowing)
- CNG SHA-256 hash of first 4KB at ImageBase in RAM (in-memory patching detection)
- Chunked reads via ReadProcessMemory (max 4MB buffer to avoid RAM exhaustion)
Alert type: ALERT_MEMORY_ANOMALY (new)

### Phase 2 — Live Mode Enhancements + Credential Detection

#### 2a. credential.c — LSASS Protection (SCAN + LIVE)
- NtQuerySystemInformation(SystemHandleInformation) — find non-system handles to lsass.exe
  with PROCESS_VM_READ / PROCESS_DUP_HANDLE rights
- Monitor %TEMP% for .dmp file creation
- Check HKLM\SYSTEM\CurrentControlSet\Control\Lsa RunAsPPL value
- Check VBS/Credential Guard status via DeviceGuard registry + WMI
Alert type: ALERT_CREDENTIAL_ACCESS (new)

#### 2b. behavior.c — Behavioral Process Analysis (SCAN + LIVE)
- NtQueryInformationProcess(ProcessCommandLineInformation) on all processes
- Flag LOLBIN abuse patterns:
    certutil -decode / -urlcache
    mshta javascript:
    regsvr32 /s /n /u /i:http
    powershell -enc
    cmd /c with ^ obfuscation
- Parent-child anomaly table:
    winword/excel/outlook -> cmd/powershell/wscript = CRITICAL
    explorer -> powershell = HIGH
    svchost -> whoami/net/ipconfig = CRITICAL
    services -> unsigned binary = HIGH
Alert type: ALERT_LOLBIN (new)
New Alert fields: char command_line[1024], char parent_process[MAX_PATH]

#### 2c. etw_consumer.c — ETW Real-Time Telemetry (LIVE enhancement)
Subscribe to:
- Microsoft-Windows-Kernel-Process (process create/delete with full cmdline)
- Microsoft-Windows-Kernel-Network (packet-level, replaces GetExtendedTcpTable polling)
- Microsoft-Windows-PowerShell (script block logging, catches obfuscated PS)
- Microsoft-Windows-DNS-Client (DNS query logging for tunneling detection)
Feeds into existing ids_alert() pipeline. Replaces polling in live mode.

### Phase 3 — Network Intelligence + Physical Vectors

#### 3a. Network beacon detection (network.c enhancement)
- Per-process connection interval tracking (stddev of inter-connection times)
- Low stddev on HTTPS (443) from non-browser process = C2 beaconing
- DNS query entropy analysis (long high-entropy subdomains = DNS tunneling)
Alert type: ALERT_C2_BEACON (new)

#### 3b. yara.c — Lightweight YARA Engine (SCAN)
- Minimal .yar parser: name { strings: $a = "text" $b = { hex } condition: any of them }
- Boyer-Moore-Horspool for fast memory scan
- Feeds ReadProcessMemory output from memory.c
- Abort region scan on first match (save CPU)
Alert type: ALERT_YARA_MATCH (new)

#### 3c. fim.c — File Integrity Monitor (SCAN baseline + LIVE watch)
- Baseline: hash critical system files (System32, SysWOW64, Drivers)
  using CNG BCryptHashData SHA-256
- Live: ReadDirectoryChangesW on critical directories
- Detect: file modified after baseline, new unsigned DLL in System32
Alert type: ALERT_FIM (new)

### Phase 4 — EDR-Grade Capabilities

#### 4a. stealth.c — Self-Protection
- PEB unlinking (InLoadOrderModuleList, InMemoryOrderModuleList)
- Clear BeingDebugged flag in PEB
- Zero NtGlobalFlag
- Token hardening: restrict PROCESS_TERMINATE to SYSTEM only
- SetProcessShutdownParameters at highest level

#### 4b. platform.c — Platform Attestation
- Secure Boot status via GetFirmwareEnvironmentVariable
- TPM presence via NCryptIsKeyHandle / platform crypto APIs
- UEFI variable enumeration for unexpected entries

#### 4c. dlp.c — Sensitive Data Discovery (SCAN)
- Scan user directories for: credit card (Luhn), SSN, IBAN, private keys (.pem), .kdbx
- Shannon entropy > 7.5 on unrecognized files = possible encrypted exfil data
- Configurable scan paths via ids.conf

#### 4d. input_monitor.c — Keylogger Detection (SCAN + LIVE)
- Enumerate global keyboard hooks via SetWindowsHookEx introspection
- GetAsyncKeyState baseline vs raw input stream comparison
- Alert on unauthorized WH_KEYBOARD_LL hooks

---

## Alert Type Registry (complete)

```c
typedef enum {
    /* Existing */
    ALERT_PORT_SCAN,
    ALERT_SUSPICIOUS_PROCESS,
    ALERT_BLOCKED_IP,
    ALERT_BRUTE_FORCE,
    ALERT_ANOMALOUS_TRAFFIC,
    ALERT_SUSPICIOUS_EVENT,
    ALERT_UNKNOWN_SERVICE,
    /* Phase 1 */
    ALERT_SUSPICIOUS_DRIVER,
    ALERT_HIDDEN_PROCESS,
    ALERT_PERSISTENCE,
    ALERT_MEMORY_ANOMALY,
    /* Phase 2 */
    ALERT_CREDENTIAL_ACCESS,
    ALERT_LOLBIN,
    ALERT_YARA_MATCH,
    /* Phase 3 */
    ALERT_C2_BEACON,
    ALERT_FIM,
    /* Phase 4 */
    ALERT_SENSITIVE_DATA,
    ALERT_KEYLOGGER,
    ALERT_PLATFORM_INTEGRITY,
} AlertType;
```

## Alert Struct Extensions (phased)

```c
typedef struct {
    /* existing fields ... */
    /* Phase 2 additions */
    char command_line[1024];     /* behavior.c: full process cmdline */
    char parent_process[MAX_PATH]; /* behavior.c: parent name */
    char technique_id[16];       /* MITRE ATT&CK e.g. "T1055" */
    /* Phase 3 */
    char rule_name[64];          /* yara.c: matched rule name */
    char file_path[MAX_PATH];    /* fim.c/dlp.c: affected file */
} Alert;
```

## Privilege Requirements

| Module | Privilege | Notes |
|--------|-----------|-------|
| memory.c | SeDebugPrivilege | OpenProcess on protected procs |
| credential.c | SeDebugPrivilege | Handle enum, LSASS inspection |
| kernel.c | SeLoadDriverPrivilege | Driver enumeration |
| etw_consumer.c | SeSystemProfilePrivilege | ETW session creation |
| fim.c | SeBackupPrivilege | Read locked files |
| stealth.c | SeDebugPrivilege | PEB manipulation |
| platform.c | SeSystemEnvironmentPrivilege | Firmware vars |

AdjustTokenPrivileges called in main.c at startup for all of the above.
Log warning (not fatal) if any privilege is denied.

## Crash Safety Rules
- All ReadProcessMemory / NtQueryInformationProcess calls wrapped in __try/__except
- Memory scanner: max 4MB buffer per VirtualQueryEx region
- Scan mode: strictly sequential (no parallel threads — avoids system thrashing)
- Live mode: WaitForSingleObject(g_shutdown_event, interval) in every loop

## New src/ Files to Create (in order)
1. src/kernel.c
2. src/rootkit.c
3. src/persistence.c
4. src/memory.c
5. src/behavior.c
6. src/credential.c
7. src/etw_consumer.c
8. src/yara.c
9. src/fim.c
10. src/stealth.c
11. src/platform.c
12. src/dlp.c
13. src/input_monitor.c

---

## Gap Analysis & Missing Capabilities

### Gap 1 — Tamper-Evident Logging (ALL profiles, CRITICAL for Federal)
**Problem**: JSONL log is a plain file. Admin attacker deletes it, evidence is gone.
**Solution**: HMAC-SHA256 chain on every log line.
  - At startup: derive a session key from CNG BCryptGenRandom
  - Each JSONL line: append "hmac":"<hex>" field = HMAC of (prev_hmac + line content)
  - Any deletion or modification breaks the chain — detectable on next open
  - Optional: forward log lines via UDP syslog to remote SIEM (ids.conf: syslog_host, syslog_port)
**Where**: alert.c (ids_log_alert) + new src/logchain.c
**New config**: syslog_host, syslog_port, log_hmac_key (derived, not stored)

### Gap 2 — Clipboard Monitor (Banking profile)
**Problem**: Clipboard hijacking (crypto address swap, credential capture) is invisible.
**Solution**: AddClipboardFormatListener in live mode.
  - Register window to receive WM_CLIPBOARDUPDATE
  - On each change: read clipboard text, check for crypto address patterns,
    password-like strings, or abnormal frequency
  - Flag: clipboard changed > N times/minute (hijacker polling)
**Where**: new src/clipboard.c, live mode only
**Alert type**: ALERT_CLIPBOARD (new)

### Gap 3 — Screen Capture / Overlay Detection (Banking profile)
**Problem**: WH_CBT hooks, mirror drivers, DXGI desktop duplication by malware.
**Solution**: Enumerate all global hooks via SetWindowsHookEx introspection.
  - EnumWindows + GetWindowLongPtr to find overlay windows (WS_EX_LAYERED + WS_EX_TRANSPARENT)
  - Check for unauthorized DXGI or mirror display adapters
  - Detect WH_CBT, WH_CALLWNDPROC global hooks from non-whitelisted processes
**Where**: extend input_monitor.c
**Alert type**: ALERT_SCREEN_CAPTURE (new)

### Gap 4 — Remote Log Forwarding (CEO + Federal profiles)
**Problem**: Logs die with the compromised machine.
**Solution**: UDP syslog forwarder in alert.c (RFC 5424 / CEF format).
  - Non-blocking UDP send after each ids_log_alert call
  - Configurable: syslog_host <ip>, syslog_port <port> in ids.conf
  - Fallback: if UDP fails, write to local log as now (never block)
**Where**: alert.c (ids_log_alert extension) + config.c (new directives)

### Gap 5 — File Write-Rate Monitor (Federal profile — anti-forensic wiping)
**Problem**: cipher /w, sdelete, bcwipe destroy evidence undetected.
**Solution**: ReadDirectoryChangesW on user directories + system drive root.
  - Track delete/overwrite rate per directory per minute
  - Threshold: > N file deletions in M seconds = ALERT_ANTIFORENSIC
  - Also: monitor Volume Shadow Copy deletion (vssadmin delete shadows)
    via process cmdline monitoring in behavior.c
**Where**: extend fim.c
**Alert type**: ALERT_ANTIFORENSIC (new)

### Gap 6 — Memory Entropy Analysis (Federal profile — encrypted payloads)
**Problem**: Encrypted/packed shellcode evades YARA string matching.
**Solution**: Shannon entropy calculation on executable memory regions.
  - In memory.c: for each MEM_PRIVATE + EXECUTE region, calculate entropy
  - Entropy > 7.2 on an executable region with no file backing = likely packed shellcode
  - Combine with size threshold (> 4KB) to reduce false positives
**Where**: memory.c (add entropy pass after VirtualQueryEx loop)

---

## Updated Alert Type Registry

```c
typedef enum {
    /* Live — network */
    ALERT_PORT_SCAN, ALERT_BLOCKED_IP, ALERT_ANOMALOUS_TRAFFIC,
    ALERT_UNKNOWN_SERVICE, ALERT_C2_BEACON,
    /* Live — process/event */
    ALERT_SUSPICIOUS_PROCESS, ALERT_BRUTE_FORCE, ALERT_SUSPICIOUS_EVENT,
    ALERT_LOLBIN, ALERT_CREDENTIAL_ACCESS,
    /* Scan — kernel/rootkit */
    ALERT_SUSPICIOUS_DRIVER, ALERT_HIDDEN_PROCESS,
    /* Scan — persistence */
    ALERT_PERSISTENCE,
    /* Scan — memory */
    ALERT_MEMORY_ANOMALY, ALERT_YARA_MATCH,
    /* Scan — files */
    ALERT_FIM, ALERT_SENSITIVE_DATA,
    /* Platform */
    ALERT_PLATFORM_INTEGRITY, ALERT_KEYLOGGER,
    /* Gap fixes */
    ALERT_CLIPBOARD,          /* Gap 2 */
    ALERT_SCREEN_CAPTURE,     /* Gap 3 */
    ALERT_ANTIFORENSIC,       /* Gap 5 */
} AlertType;
```

## Coverage After Gap Fixes

| Profile  | Before | After gap fixes |
|----------|--------|-----------------|
| CEO      | ~70%   | ~85%            |
| Federal  | ~45%   | ~75%            |
| Banking  | ~55%   | ~80%            |

Remaining uncovered (by design — require kernel driver):
- UEFI implant detection (needs ring-0 or firmware access)
- Kernel-level keyboard filter (needs signed driver)
- Hardware keylogger (physically undetectable from OS)
- Encrypted C2 payload inspection (needs TLS MITM proxy)
