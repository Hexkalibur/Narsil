📄 Module Report 5: network.c (Network Monitor)
Current State (What We Have)
Inspects the TCP/UDP connection tables every 3 seconds. Attributes connections to PIDs, checks for blocked IPs, suspicious ports, port scans, and anomalous staging paths. 
Critical Flaws: Uses GetExtendedTcpTable (polling), which misses short-lived connections (like malware beaconing). Contains a critical pointer bug (PidEntry e = pid_find instead of *e). The is_stage_path function uses single backslashes (\temp\), which C interprets as escape characters (Tab), rendering the check blind.
Target Vision (What We Want to Achieve)
Real-time, kernel-level network telemetry. We must move from "polling the state" to "observing the events." Narsil will track network flows, inspect DNS, and detect behavioral Command & Control (C2) patterns.
Meticulous Functional Breakdown

    pid_cache_refresh / pid_find: 
        Current: Polls CreateToolhelp32Snapshot, contains pointer bugs.
        Target: Will transition to consuming ETW (Event Tracing for Windows) Process events to maintain a real-time, zero-polling PID-to-Path mapping. If polling is kept as a fallback, pointer logic will be strictly corrected.
    check_tcp / check_udp: 
        Current: Polls GetExtendedTcpTable, misses ephemeral connections.
        Target: Will integrate WinDivert or ETW NetTCPIP providers to capture raw connection events asynchronously. This allows Narsil to see a connection the millisecond it is established, even if it closes a second later.
    is_private_ip: 
        Current: Uses obscure, hard-to-read bit-shifting math.
        Target: Will use highly optimized, readable subnet masking, pre-calculated at compile time for maximum CPU cache efficiency.
    tracker_get (Port Scan & Anomaly Detection): 
        Current: Simple sliding window counter.
        Target: Advanced heuristics. Will track SYN/ACK ratios to detect stealthy SYN scans, monitor DNS query entropy to detect DNS tunneling, and correlate outbound connections to external IPs with the process's digital signature reputation.