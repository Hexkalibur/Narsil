📄 Module Report 7: events.c (Event Log Monitor)
Current State (What We Have)
Subscribes to Windows Security, System, and Application logs. Extracts data via naive string searching and tracks brute-force attempts. 
Critical Flaws: process_event is missing a pointer. The XML parser looks for <EventID > (with a space) and <IpAddress>, but Windows Event XML uses <EventID> (no space) and nests IPs inside <Data Name="IpAddress">. The parser extracts nothing. Typo corruption (EVT_A CCOUNT_LOCKOUT) breaks compilation.
Target Vision (What We Want to Achieve)
Advanced Windows Event correlation and Sysmon integration. Narsil will act as a local correlation engine, stitching together disparate events to detect complex attack chains (like Lateral Movement or Defense Evasion).
Meticulous Functional Breakdown

    subscribe_channel: 
        Current: Basic pull-based loop, vulnerable to channel clearing.
        Target: Will use highly optimized XPath queries pushed down to the Windows Event Log service to filter events at the kernel level, saving CPU. It will gracefully handle scenarios where an admin clears the Security log (a massive red flag in itself).
    xml_extract: 
        Current: Naive strstr that fails on nested tags and attributes.
        Target: A dedicated, lightweight XML state-machine parser specifically tuned for the Windows Event XML schema. It will correctly parse attributes (e.g., extracting the Name attribute from <Data> tags).
    process_event (Correlation Engine): 
        Current: Broken tags, isolated event processing.
        Target: Will maintain a local state table. It will correlate events across channels (e.g., matching a Process Creation event in Security with a Service Installation in System). It will enrich events by cross-referencing the PID with the network.c and process.c modules.
    brute_get (Brute-Force & Credential Attack Tracker): 
        Current: Simple IP-based counter.
        Target: Will track Usernames in addition to IPs to detect Password Spraying (one password tried against many users). It will also integrate with GeoIP to flag logons from impossible locations or unexpected countries.

