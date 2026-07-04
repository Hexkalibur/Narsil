# Narsil

<p align="center">
  <img src="01.jpg" alt="Narsil" width="100">
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
| **processes** | Known-bad names, parent-child anomalies (Office to shell), staging paths, signature tiers |
| **memory** | Committed private RWX regions, the classic footprint of injected shellcode |
| **network** | Active TCP/UDP endpoints: blocked IPs, suspicious ports, processes phoning home from staging paths |
| **events** | Recent Security/System event log entries: brute force, new users/services, log clearing |

Findings are mapped to MITRE ATT&CK technique IDs.

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
log_path        <path>     # alert JSONL log destination
blocked_ip      <ip>       # flag any connection to/from this IP
suspicious_port <port>     # flag any endpoint on this port
verbose                    # enable debug output

# Skip individual scan modules (all run by default):
no_kernel  no_rootkit  no_persistence
no_process  no_memory  no_network  no_events
```

## Requirements

- Windows (x64)
- Administrator privileges (Narsil enables `SeDebugPrivilege`,
  `SeLoadDriverPrivilege`, and related privileges at startup)
