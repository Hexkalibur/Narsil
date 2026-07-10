/*
 * events.c -- Windows Event Log scanner.
 *
 * Reads the last N hours of Security and System event logs,
 * extracts events of interest, and flags anomalies:
 *   - Failed logons + brute-force pattern
 *   - Account lockouts
 *   - Audit policy changes
 *   - New user accounts created
 *   - New services installed
 *   - Process creation with suspicious cmdline
 *   - Log clearing (event 1102 / 104)
 *
 * No threads, no subscription. One-shot query, then returns.
 */
#include "../include/ids.h"
#include "../include/report.h"

/* Default lookback if the operator doesn't override events_hours in the
   config file (see cfg->events_hours_back, default 24). */
#define BRUTE_THRESHOLD     5    /* failed logons within window = brute force */
#define BRUTE_WINDOW_SECS 300    /* 5 minutes */
#define MAX_EVENTS_READ   4096

/* Event IDs of interest */
#define EVT_LOGON_FAILURE     4625
#define EVT_ACCOUNT_LOCKOUT   4740
#define EVT_AUDIT_CHANGE      4719
#define EVT_USER_CREATED      4720
#define EVT_PRIVILEGE_USE     4673
#define EVT_PROCESS_CREATION  4688
#define EVT_SERVICE_INSTALLED 7045
#define EVT_LOG_CLEARED_SEC   1102
#define EVT_LOG_CLEARED_SYS    104

/* Microsoft-Windows-Windows Defender/Operational channel */
#define EVT_DEFENDER_DETECTION 1116
#define EVT_DEFENDER_ACTION_FAIL 1119

/* -----------------------------------------------
   Minimal XML field extractor
   Handles both:
     <Tag ...>value</Tag>   (xml_extract_tag)
     <Data Name="k">v</Data>  (xml_extract_data)
   ----------------------------------------------- */
static BOOL xml_extract_tag(const char *xml, const char *tag,
                             char *out, size_t out_len) {
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "<%s", tag);
    const char *p = strstr(xml, prefix);
    if (!p) return FALSE;
    p = strchr(p, '>');
    if (!p) return FALSE;
    p++;
    char close[64];
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *end = strstr(p, close);
    if (!end) return FALSE;
    size_t len = (size_t)(end - p);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return TRUE;
}

static BOOL xml_extract_data(const char *xml, const char *name,
                              char *out, size_t out_len) {
    char needle[128];
    snprintf(needle, sizeof(needle), "Name=\"%s\"", name);
    const char *p = xml;
    while ((p = strstr(p, needle)) != NULL) {
        const char *tag = p;
        while (tag > xml && *tag != '<') tag--;
        if (strncmp(tag, "<Data", 5) != 0) { p++; continue; }
        const char *content = strchr(p, '>');
        if (!content) return FALSE;
        content++;
        const char *end = strstr(content, "</Data>");
        if (!end) return FALSE;
        if (end - content == 1 && *content == '-') return FALSE;
        size_t len = (size_t)(end - content);
        if (len >= out_len) len = out_len - 1;
        memcpy(out, content, len);
        out[len] = '\0';
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------
   Render EVT_HANDLE to XML string
   ----------------------------------------------- */
static BOOL render_xml(EVT_HANDLE hEvent, char *buf, DWORD buf_len) {
    WCHAR wide[8192] = {0};
    DWORD used = 0, props = 0;
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml,
                   sizeof(wide), wide, &used, &props))
        return FALSE;
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, buf, buf_len - 1, NULL, NULL);
    return TRUE;
}

/* -----------------------------------------------
   Brute-force tracker (per source IP)
   ----------------------------------------------- */
#define BRUTE_CAP 128
typedef struct { char ip[MAX_IP_LEN]; DWORD count; time_t first; } BruteEntry;
static BruteEntry g_brute[BRUTE_CAP];
static int        g_brute_n = 0;

static BruteEntry *brute_get(const char *ip) {
    for (int i = 0; i < g_brute_n; i++)
        if (strcmp(g_brute[i].ip, ip) == 0) return &g_brute[i];
    if (g_brute_n >= BRUTE_CAP) return NULL;
    BruteEntry *e = &g_brute[g_brute_n++];
    strncpy(e->ip, ip, MAX_IP_LEN - 1);
    e->count = 0; e->first = time(NULL);
    return e;
}

/* -----------------------------------------------
   Process one event
   ----------------------------------------------- */
static void process_event(IdsConfig *cfg, ScanReport *rep,
                          EvidenceTable *tbl, EVT_HANDLE hEvent) {
    char xml[8192] = {0};
    if (!render_xml(hEvent, xml, sizeof(xml))) return;

    char id_str[16] = {0};
    if (!xml_extract_tag(xml, "EventID", id_str, sizeof(id_str))) return;
    DWORD eid = (DWORD)atol(id_str);

    /* Extract common fields */
    char src_ip[MAX_IP_LEN]  = {0};
    char username[128]        = {0};
    char proc_name[MAX_PATH]  = {0};

    xml_extract_data(xml, "IpAddress",      src_ip,    sizeof(src_ip));
    xml_extract_data(xml, "TargetUserName", username,  sizeof(username));
    if (!username[0])
        xml_extract_data(xml, "SubjectUserName", username, sizeof(username));
    xml_extract_data(xml, "NewProcessName", proc_name, sizeof(proc_name));

    Alert a = {0};
    a.type      = ALERT_SUSPICIOUS_EVENT;
    a.timestamp = time(NULL);
    strncpy(a.source_ip, src_ip, MAX_IP_LEN - 1);

    char ev_label[64];
    snprintf(ev_label, sizeof(ev_label), "EventID %lu", eid);

    switch (eid) {

        case EVT_LOGON_FAILURE: {
            const char *src = src_ip[0] ? src_ip : "local";
            BruteEntry *b   = brute_get(src);
            if (!b) break;

            if (time(NULL) - b->first > BRUTE_WINDOW_SECS) {
                b->count = 1; b->first = time(NULL);
            } else {
                b->count++;
                if (b->count >= BRUTE_THRESHOLD) {
                    a.type     = ALERT_BRUTE_FORCE;
                    a.severity = SEV_HIGH;
                    snprintf(a.description, MAX_DESCRIPTION,
                             "Brute-force: %lu failed logons in %ds from %s (user=%s)",
                             b->count, BRUTE_WINDOW_SECS, src,
                             username[0] ? username : "?");
                    b->count = 0; b->first = time(NULL);
                    report_add(rep, &a); ids_log_alert(cfg, &a);
                    report_table_add(tbl, src_ip, "brute-force", ev_label,
                                     ENTRY_FLAGGED, a.description);
                }
            }
            return; /* don't emit individual 4625 unless brute threshold hit */
        }

        case EVT_ACCOUNT_LOCKOUT: {
            char locked[128] = {0};
            xml_extract_data(xml, "TargetUserName", locked, sizeof(locked));
            a.severity = SEV_HIGH;
            snprintf(a.description, MAX_DESCRIPTION,
                     "Account lockout (4740) user=%s",
                     locked[0] ? locked : "?");
            break;
        }

        case EVT_AUDIT_CHANGE:
            a.severity = SEV_CRITICAL;
            snprintf(a.description, MAX_DESCRIPTION,
                     "Audit policy changed (4719) -- possible log tampering");
            strncpy(a.technique_id, "T1562", sizeof(a.technique_id) - 1);
            break;

        case EVT_USER_CREATED: {
            char newuser[128] = {0};
            xml_extract_data(xml, "TargetUserName", newuser, sizeof(newuser));
            a.severity = SEV_HIGH;
            snprintf(a.description, MAX_DESCRIPTION,
                     "New user created (4720) name=%s by=%s",
                     newuser[0] ? newuser : "?",
                     username[0] ? username : "?");
            strncpy(a.technique_id, "T1136", sizeof(a.technique_id) - 1);
            break;
        }

        case EVT_SERVICE_INSTALLED: {
            char svc[128] = {0}, img[MAX_PATH] = {0};
            xml_extract_data(xml, "ServiceName", svc, sizeof(svc));
            xml_extract_data(xml, "ImagePath",   img, sizeof(img));
            a.severity = SEV_HIGH;
            snprintf(a.description, MAX_DESCRIPTION,
                     "New service installed (7045) name=%s path=%s",
                     svc[0] ? svc : "?", img[0] ? img : "?");
            strncpy(a.technique_id, "T1543", sizeof(a.technique_id) - 1);
            if (img[0]) strncpy(a.file_path, img, MAX_PATH - 1);
            break;
        }

        case EVT_PROCESS_CREATION: {
            /* Command-line auditing must be enabled via GPO for this field
               to be populated; if absent we still get the image name. */
            char cmdline[512] = {0};
            xml_extract_data(xml, "CommandLine", cmdline, sizeof(cmdline));

            const NarsilPattern *m = narsil_match_pattern(cmdline[0] ? cmdline : proc_name);
            strncpy(a.process_name, proc_name, MAX_PATH - 1);

            if (m) {
                a.type     = ALERT_SUSPICIOUS_CMDLINE;
                a.severity = m->sev;
                strncpy(a.technique_id, m->mitre, sizeof(a.technique_id) - 1);
                snprintf(a.description, MAX_DESCRIPTION,
                         "%s: process created (4688) name=%s user=%s cmdline: %.150s",
                         m->why, proc_name[0] ? proc_name : "?",
                         username[0] ? username : "?", cmdline);
                break;
            }

            /* No suspicious pattern -- low severity, evidence only. */
            a.severity = SEV_LOW;
            snprintf(a.description, MAX_DESCRIPTION,
                     "Process created (4688) name=%s user=%s",
                     proc_name[0] ? proc_name : "?",
                     username[0]  ? username  : "?");
            report_table_add(tbl, proc_name, proc_name, ev_label, ENTRY_OK,
                             username[0] ? username : "");
            return;
        }

        case EVT_LOG_CLEARED_SEC:
        case EVT_LOG_CLEARED_SYS:
            a.severity = SEV_CRITICAL;
            snprintf(a.description, MAX_DESCRIPTION,
                     "Event log cleared (EventID=%lu) by %s -- anti-forensic indicator",
                     eid, username[0] ? username : "?");
            strncpy(a.technique_id, "T1070", sizeof(a.technique_id) - 1);
            break;

        case EVT_DEFENDER_DETECTION: {
            char threat[256] = {0}, path[MAX_PATH] = {0};
            xml_extract_data(xml, "Threat Name", threat, sizeof(threat));
            xml_extract_data(xml, "Path",        path,   sizeof(path));
            a.type     = ALERT_DEFENDER_EVENT;
            a.severity = SEV_CRITICAL;
            if (path[0]) strncpy(a.file_path, path, MAX_PATH - 1);
            snprintf(a.description, MAX_DESCRIPTION,
                     "Windows Defender detection (1116): %s%s%s -- Narsil's own "
                     "process/memory findings should be cross-checked against this",
                     threat[0] ? threat : "unknown threat",
                     path[0] ? " @ " : "", path);
            break;
        }

        case EVT_DEFENDER_ACTION_FAIL:
            a.type     = ALERT_DEFENDER_EVENT;
            a.severity = SEV_HIGH;
            snprintf(a.description, MAX_DESCRIPTION,
                     "Windows Defender remediation FAILED (1119) -- threat may still "
                     "be active on this host");
            break;

        default:
            return;
    }

    report_add(rep, &a);
    ids_log_alert(cfg, &a);
    report_table_add(tbl, src_ip[0] ? src_ip : "-",
                     username[0] ? username : "?",
                     ev_label, ENTRY_FLAGGED, a.description);
}

/* -----------------------------------------------
   Query one channel for the last N hours
   ----------------------------------------------- */
static void query_channel(IdsConfig *cfg, ScanReport *rep,
                           EvidenceTable *tbl, const wchar_t *channel,
                           int hours_back) {

    ULONGLONG ms = (ULONGLONG)hours_back * 3600 * 1000;
    wchar_t xpath[256];
    swprintf(xpath, 256,
             L"Event/System[TimeCreated[timediff(@SystemTime) <= %I64u]]",
             ms);

    EVT_HANDLE hQuery = EvtQuery(NULL, channel, xpath,
                                  EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hQuery) {
        char buf[WIN_ERR_BUF]; WIN_ERR_STR(GetLastError(), buf);
        LOG_WARN("events: EvtQuery failed on channel (err=%s)", buf);
        return;
    }

    EVT_HANDLE batch[64];
    DWORD      returned = 0;
    int        processed = 0;

    while (processed < MAX_EVENTS_READ &&
           EvtNext(hQuery, 64, batch, 1000, 0, &returned)) {
        for (DWORD i = 0; i < returned; i++) {
            process_event(cfg, rep, tbl, batch[i]);
            EvtClose(batch[i]);
            processed++;
        }
    }

    EvtClose(hQuery);
    LOG_DBG("events: channel processed: %d events", processed);
}

/* -----------------------------------------------
   Public entry point
   ----------------------------------------------- */
void ids_scan_events(IdsConfig *cfg, ScanReport *rep) {
    int hours = cfg->events_hours_back > 0 ? cfg->events_hours_back : 24;
    LOG_INFO("scan: event logs (last %d hours)...", hours);

    EvidenceTable *tbl = report_table_begin(rep, "events");

    query_channel(cfg, rep, tbl, L"Security", hours);
    query_channel(cfg, rep, tbl, L"System", hours);
    query_channel(cfg, rep, tbl,
                  L"Microsoft-Windows-Windows Defender/Operational", hours);

    LOG_INFO("scan: events -- done  processed=%d  flagged=%d",
             tbl->count, tbl->flagged_count);
}