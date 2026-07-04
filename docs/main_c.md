📄 Module Report 2: main.c (Entry Point & Lifecycle Management)
Current State (What We Have)
This module handles CLI argument parsing, initializes Winsock, spawns the monitor threads, and waits for a Ctrl-C signal to shut down. 
Critical Flaws: CLI argument parsing contains trailing spaces (e.g., "-h "), making flags unrecognizable. The shutdown sequence uses TerminateThread(), a catastrophic API call that corrupts heap memory, abandons locks, and leaves the system in an undefined state.
Target Vision (What We Want to Achieve)
Narsil must operate as a resilient, enterprise-grade daemon. The lifecycle manager must support Windows Service integration, enforce administrative privileges, and execute flawless, graceful shutdowns without leaking resources.
Meticulous Functional Breakdown

    ctrl_handler (Signal Handling): 
        Current: Simply flips a g_running boolean. Threads ignore this and must be violently killed.
        Target: Will signal global Windows Event Objects (CreateEvent). Monitor threads will wait on these events alongside their sleep timers, allowing them to wake up and exit gracefully the millisecond shutdown is requested.
    ids_run (Engine Orchestrator): 
        Current: Spawns threads and uses TerminateThread to kill them.
        Target: Will act as a supervisor. It will monitor thread health, automatically restart crashed modules, and use WaitForMultipleObjects on the shutdown events to cleanly join threads before exiting.
    main (Entry Point): 
        Current: Basic strcmp loop with trailing space bugs.
        Target: Robust argument parser. Will include flags for installing/uninstalling Narsil as a Windows Service (--install, --remove), and will explicitly check for Administrator/SYSTEM privileges on startup, exiting cleanly with a clear error if lacking rights.