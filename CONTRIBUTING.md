# Contributing to Narsil

Thanks for your interest in improving Narsil. It is a scan-only Windows
host-compromise scanner written in plain C against the Win32/NT APIs.
Contributions of bug fixes, new detections, documentation, and testing on
additional Windows versions are all welcome.

## Building

Requires a C toolchain for Windows. Both of these work:

- **MSYS2 / MinGW-w64** (native build): from the `MINGW64` shell,
  `pacman -S mingw-w64-x86_64-gcc make`, then `make`.
- **MinGW-w64 cross-compiler on Linux**: `make CC=x86_64-w64-mingw32-gcc`
  (this is what the CI uses).

Either way the build produces `narsil.exe`. See the README for usage and
`ids.conf.example` for the configuration directives.

## Coding style

- **Language:** plain C, no C++. Keep to the Win32/NT and C runtime APIs
  already used in the tree.
- **Indentation:** 4 spaces, no tabs.
- **String handling / logging:** reuse the existing helpers and macros
  (`snprintf`, `strncpy`, and the `LOG_INFO` / `LOG_WARN` / `LOG_ERR` /
  `LOG_DBG` macros) rather than introducing new conventions.
- **Scope:** keep diffs minimal and focused; avoid reformatting or
  refactoring code unrelated to your change.
- Narsil is **scan-only** by design: it reads system state and reports.
  Contributions should not add code that modifies the host, persists, or
  performs any offensive action.

## Submitting a pull request

1. Fork the repository and create a topic branch.
2. Make your change with a clear commit message describing what and why.
3. Confirm the project still builds cleanly with `make`.
4. Open a pull request describing the change and how you tested it (which
   Windows version, elevated or not, what the report showed).

## Detection changes

Because Narsil's usefulness depends on a low false-positive rate, changes
that add or alter detection logic should include a short rationale for
their false-positive impact: what legitimate software might trip the new
check, and how the check distinguishes benign from malicious behaviour.

The v0.2 memory-scanner rework is the reference example -- it exists
specifically to stop flagging every JIT/CLR host's RWX memory as an
injection (v0.1 raised ~79 false HIGH alerts on a normal desktop), and its
commit message documents that reasoning. New detections are expected to
reason about noise in the same way.

## Reporting bugs and false positives

Use the issue templates. For a false positive or false negative, please
include the process / driver / connection / event that was misclassified
and why you believe the classification is wrong, along with your Windows
version and whether Narsil was run elevated.
