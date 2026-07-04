📄 Module Report 6: process.c (Process Monitor)
Current State (What We Have)
Polls running processes and applies a 3-tier detection logic: 1) Known-bad names, 2) Unsigned binaries in staging directories, 3) Invalid digital signatures. 
Critical Flaws: sig_verify is missing a pointer (const char path), guaranteeing an access violation crash. BAD_NAMES contains trailing spaces, making name-matching completely blind. STAGE_DIRS uses single backslashes, failing path matching. 
Target Vision (What We Want to Achieve)
Deep process introspection and anti-evasion. Narsil will not just look at process names; it will analyze process lineage, command-line arguments, memory characteristics, and anti-tamper protections.
Meticulous Functional Breakdown

    sig_verify (Authenticode Verification): 
        Current: Missing pointer, crashes immediately.
        Target: Robust implementation of WinVerifyTrust. It will correctly cache results, but more importantly, it will check for revoked certificates and detect if a binary is signed with a "Test" certificate or if the signature was stripped post-compilation.
    get_integrity: 
        Current: Returns strings with trailing spaces (e.g., "low ").
        Target: Clean string returns. Will be expanded to also extract UIAccess tokens and SeDebugPrivilege status, which are massive indicators of privilege escalation attempts.
    ids_check_processes (Detection Engine): 
        Current: Polls snapshots, relies on easily bypassed name matching.
        Target: Will subscribe to Process Creation ETW events to catch processes at birth. It will track parent-child lineage (e.g., alerting if winword.exe spawns cmd.exe). It will also check for Process Hollowing by comparing the executable path on disk with the memory-mapped image name.
    is_stage_path: 
        Current: Broken escape sequences, blind to actual paths.
        Target: Will canonicalize paths (resolving short 8.3 names and symlinks) and check the ACLs (Access Control Lists) of the directory. If a binary is running from a world-writable directory, it triggers an alert, regardless of the folder name.