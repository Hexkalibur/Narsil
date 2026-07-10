# Narsil

<p align="center">
  <img src="01.png" alt="Narsil" width="100">
</p>

![Makefile CI](https://github.com/Hexkalibur/Narsil/actions/workflows/makefile.yml/badge.svg)



## The project is still in its initial phase and needs several improvements!!


A Windows security scanner. Narsil answers one question:
*"Is my machine compromised right now?"* It runs a deep, one-shot analysis
of the system using native Windows APIs only, with no heavy external
dependencies and a minimal footprint. It is scan-only: it inspects the
system and exits, leaving no resident process.

## Features

Narsil runs seven scan modules in sequence and collects their findings
into a single report:

| Module | What it checks |
|--------|----------------|
| **kernel** | Driver enumeration + Authenticode/catalog signature check (unsigned, tampered, anonymous, non-standard path) |
| **rootkit** | Hidden-process detection by cross-referencing `NtQuerySystemInformation` against the Toolhelp snapshot |
| **persistence** | Registry Run/RunOnce keys, Winlogon `Userinit`/`Shell` hijacks, and Win32 services in staging paths |
| **processes** | Known-bad names, command-line pattern matching (encoded PowerShell, LOLBins, ransomware indicators), parent-child anomalies (Office to shell), staging paths, signature tiers |
| **memory** | RWX regions triaged by content (mapped-PE detection) and thread-start correlation, not raised as noise per region |
| **network** | Active TCP/UDP endpoints: blocked IPs/CIDR ranges, suspicious ports, staging-path processes phoning home, multi-endpoint beacon heuristic |
| **events** | Recent Security/System/Defender-Operational event log entries: brute force, new users/services, log clearing, suspicious 4688 command lines, Defender detections |

Findings are mapped to MITRE ATT&CK technique IDs.

### v0.2 highlights

v0.1's memory scanner alerted on every process holding a single private
RWX region, which floods a normal desktop with false positives (JIT
engines, browsers, Defender's own AMSI host, one alert per
`backgroundTaskHost.exe` instance). v0.2 keeps the same region walk but
adds evidence before raising severity:

- **Mapped-PE detection**: private executable regions are read back and
  checked for an `MZ`/`PE` header. A manually mapped module in private
  memory is treated as a near-certain reflective-injection indicator
  (`INJECTED_PE`, CRITICAL) regardless of which process it's in.
- **Thread-start correlation**: every thread's Win32 start address is
  resolved and checked against private executable regions. A thread whose
  entry point lives in private, non-image memory is the signature of
  `CreateRemoteThread`/APC shellcode (`INJECTED_THREAD`, CRITICAL).
- **JIT allow-list**: browsers, `.NET`/CLR hosts and Defender's own AMSI
  process are recognized by default; plain RWX with no PE/thread evidence
  in these is recorded as evidence, not raised as an alert. Configurable
  via `allow_rwx` in `ids.conf`. `memory_strict` restores the raw v0.1
  behavior for analysts who want it.

Other v0.2 additions: command-line pattern matching shared between the
process scanner and 4688 event records (encoded PowerShell, LOLBin proxy
execution, ransomware/anti-forensic indicators), CIDR-range IP blocking,
a Defender-operational-log correlation, a same-scan multi-endpoint beacon
heuristic for staging-path processes, operator-defined alert suppression,
and an expanded known-ports list so routine Windows services (NTP,
NetBIOS, DHCP, SSDP, LLMNR, mDNS, WS-Discovery, IKE) stop being flagged as
`UNKNOWN_SERVICE`.

## Build

Requires a C toolchain for Windows (MSVC or MinGW-w64).

```sh
make
```

This produces `narsil.exe`. The build links against
`ws2_32`, `iphlpapi`, `wevtapi`, `psapi`, `wintrust`, `crypt32`, `advapi32`.

## Usage

Run from an elevated command prompt (Administrator is required):

```
narsil.exe [-c <conf>] [-r <rules.yar>] [-o <report.md>] [-v] [-h]
```

| Flag | Meaning |
|------|---------|
| `-c <conf>` | Config file (blocked IPs, suspicious ports, module toggles) |
| `-r <rules.yar>` | YARA rules file (reserved for memory/file matching) |
| `-o <report.md>` | Report output path (default: `narsil_report.md`) |
| `-v` | Verbose / debug output |
| `-h` | Help |

## Output

Each run writes three kinds of artifact:

- `<report>.md`: human-readable report (summary, alerts, evidence tables)
- `<report>.jsonl`: machine-readable alerts, SIEM-ready
- `<report>_<module>.csv`: full per-module evidence list

## Configuration

Copy `ids.conf.example` to `ids.conf` and pass it with `-c`. Supported
directives:

```
log_path        <path>       # alert JSONL log destination
blocked_ip      <ip[/cidr]>  # flag any connection to/from this IP or block
suspicious_port <port>       # flag any endpoint on this port
verbose                      # enable debug output

# Skip individual scan modules (all run by default):
no_kernel  no_rootkit  no_persistence
no_process  no_memory  no_network  no_events

# v0.2 -- noise control
allow_rwx        <exe name>  # don't alert plain RWX findings in this process
memory_strict                # restore v0.1: one HIGH alert per RWX region
suppress         <substring> # drop any alert whose description matches
known_udp_port   <port>      # extra port not flagged as unknown service
known_tcp_port   <port>      # extra port not flagged as unknown service
events_hours     <n>         # event-log lookback window (default 24)
```

## Requirements

- Windows (x64)
- Administrator privileges (Narsil enables `SeDebugPrivilege`,
  `SeLoadDriverPrivilege`, and related privileges at startup)
