---
name: Bug report
about: Report incorrect behaviour, a crash, or a false positive/negative
title: "[bug] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what went wrong.

**Which scan module**
kernel / rootkit / persistence / process / memory / network / events, or
"whole run" if it is not specific to one module.

**To reproduce**
Steps or the exact command line used, e.g. `narsil.exe -c ids.conf`.

**Expected behaviour**
What you expected Narsil to report instead.

**False positive / false negative**
If this is a detection-accuracy issue, describe the process, driver,
connection, or event that was misclassified, and why you believe the
classification is wrong.

**Environment**
 - Windows version and architecture (e.g. Windows 11 23H2 x64)
 - Narsil version (see `IDS_VERSION`, e.g. 0.2.0)
 - Toolchain used to build (MSVC / MinGW-w64)
 - Whether run elevated (administrator) or not

**Report output**
If possible, attach or paste the relevant lines from the generated
`.md` / `.jsonl` report (redact anything sensitive such as internal IPs
or hostnames).

**Additional context**
Anything else that helps reproduce or understand the issue.
