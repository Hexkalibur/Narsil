# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `known_tcp_port` config directive is now honoured. It was parsed into
  `known_tcp_ports[]` but never read, so it had no effect; TCP known-port
  checks now consult it, and a symmetric UNKNOWN_SERVICE check was added
  for listening TCP ports.
- `memory_strict` no longer performs the v0.2 triage work (thread-start
  collection, PE content inspection) whose results it discards, restoring
  the v0.1 cost profile in strict mode.

### Added
- Warning logged once when `NtQueryInformationThread` cannot be resolved,
  making it visible that thread-start correlation (injected-thread
  detection) is disabled for that run.
- `CONTRIBUTING.md`, this changelog, and GitHub issue templates.
- CI now attaches a SHA256 checksum alongside the release binary.

## [0.2.0] - 2026-07-04

### Changed
- Memory scanner reworked around evidence-based triage instead of one HIGH
  alert per private RWX region. Regions are inspected for a mapped PE
  header (`INJECTED_PE`, CRITICAL) and correlated against thread start
  addresses (`INJECTED_THREAD`, CRITICAL); plain RWX in known JIT/CLR hosts
  is recorded as evidence rather than alerted. `memory_strict` restores the
  v0.1 one-HIGH-per-region behaviour.

### Added
- Command-line pattern matching shared between the live process scanner and
  4688 event records (encoded PowerShell, LOLBin proxy execution,
  ransomware / anti-forensic indicators).
- CIDR-range IP blocking for `blocked_ip`.
- Windows Defender Operational log correlation.
- Same-scan multi-endpoint beacon heuristic for staging-path processes.
- Operator-defined alert suppression (`suppress`) and configurable
  event-log lookback window (`events_hours`).
- Expanded known-ports list so routine Windows services (NTP, NetBIOS,
  DHCP, SSDP, LLMNR, mDNS, WS-Discovery, IKE) are no longer flagged as
  `UNKNOWN_SERVICE`.
- Shared helpers centralized in `src/util.c` (staging-path checks,
  Authenticode / catalog verification, IP-block matching).

## [0.1.0] - 2026-07-04

### Added
- Initial release: seven scan modules (kernel, rootkit, persistence,
  process, memory, network, events) producing a combined report with
  findings mapped to MITRE ATT&CK technique IDs.
