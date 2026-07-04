📄 Module Report 4: alert.c (Alert Dispatch & Telemetry)
Current State (What We Have)
Handles formatting alerts for the console (with colors) and writing them to a local text file. 
Critical Flaws: The log file uses a pipe (|) delimiter. If an alert description contains a pipe or a newline character, it breaks the log format, ruining SIEM ingestion. The logging is synchronous, meaning a slow disk will block the network/process monitor threads.
Target Vision (What We Want to Achieve)
A high-throughput, standardized telemetry pipeline. Narsil must output data in formats that enterprise tools (Splunk, ELK, Sentinel) can ingest natively without custom parsers. It must never block the detection engine.
Meticulous Functional Breakdown

    ids_alert (Dispatcher): 
        Current: Synchronously prints and logs, blocking the calling thread.
        Target: Will push the Alert struct into a lock-free (or highly optimized locked) ring buffer. A dedicated background "Dispatcher Thread" will drain this buffer and handle I/O, ensuring the detection engines never wait on disk or console I/O.
    ids_print_alert (Console Output): 
        Current: Basic printf with color codes.
        Target: Will support a "structured mode" that outputs pretty-printed JSON to the console for power users piping output to tools like jq.
    ids_log_alert (File/Syslog Output): 
        Current: Pipe-delimited fprintf, vulnerable to log injection.
        Target: Will output JSON Lines (JSONL) format. Every alert is a single, perfectly escaped JSON object. It will also support atomic file writes and log rotation, and optionally forward via UDP Syslog (CEF/LEEF format).
    Helper Functions (ids_severity_str, etc.): 
        Current: Basic string returns.
        Target: Will append standardized metadata (e.g., mapping SEV_CRITICAL to a numeric CVSS-like score for automated SOAR playbook triggering).