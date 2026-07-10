/*
 * report.c -- Scan report: alerts + evidence tables -> .md + .jsonl + .csv
 */
#include "../include/ids.h"
#include "../include/report.h"

typedef struct { int critical, high, medium, low; } SevCount;

static SevCount count_sev(const ScanReport *r) {
    SevCount c = {0};
    for (int i = 0; i < r->count; i++) {
        switch (r->alerts[i].severity) {
            case SEV_CRITICAL: c.critical++; break;
            case SEV_HIGH:     c.high++;     break;
            case SEV_MEDIUM:   c.medium++;   break;
            default:           c.low++;      break;
        }
    }
    return c;
}

static const char *entry_status_str(EntryStatus s) {
    switch (s) {
        case ENTRY_OK:      return "OK";
        case ENTRY_SKIPPED: return "SKIPPED";
        case ENTRY_WARN:    return "WARN";
        case ENTRY_FLAGGED: return "FLAGGED";
        default:            return "?";
    }
}

/* -----------------------------------------------
   Public API — lifecycle
   ----------------------------------------------- */
ScanReport *report_create(const char *md_path, const char *jsonl_path) {
    ScanReport *r = (ScanReport *)calloc(1, sizeof(ScanReport));
    if (!r) { LOG_ERR("report_create: out of memory"); return NULL; }
    r->scan_start = time(NULL);
    strncpy(r->report_path, md_path    ? md_path    : "narsil_report.md",  MAX_LOG_PATH - 1);
    strncpy(r->jsonl_path,  jsonl_path ? jsonl_path : "narsil_scan.jsonl", MAX_LOG_PATH - 1);
    LOG_DBG("report created: md=%s jsonl=%s", r->report_path, r->jsonl_path);
    return r;
}

void report_free(ScanReport *r) { if (r) free(r); }

/* -----------------------------------------------
   Alerts
   ----------------------------------------------- */
void report_add(ScanReport *r, const Alert *a) {
    if (!r || !a) return;
    if (g_active_cfg && ids_alert_suppressed(g_active_cfg, a)) return;
    if (r->count >= REPORT_MAX_ALERTS) {
        LOG_WARN("report_add: buffer full (%d), dropping alert", REPORT_MAX_ALERTS);
        return;
    }
    r->alerts[r->count] = *a;
    if (r->alerts[r->count].timestamp == 0)
        r->alerts[r->count].timestamp = time(NULL);
    r->count++;
    ids_print_alert(&r->alerts[r->count - 1]);
    LOG_DBG("alert #%d: [%s] %s", r->count,
            ids_alert_type_str(a->type), a->description);
}

/* -----------------------------------------------
   Evidence tables
   ----------------------------------------------- */
EvidenceTable *report_table_begin(ScanReport *r, const char *module) {
    if (!r || r->table_count >= 16) return NULL;
    EvidenceTable *t = &r->tables[r->table_count++];
    memset(t, 0, sizeof(*t));
    strncpy(t->module, module, sizeof(t->module) - 1);
    LOG_DBG("evidence table started: %s", module);
    return t;
}

void report_table_add(EvidenceTable *t, const char *path,
                      const char *name, const char *detail,
                      EntryStatus status, const char *reason) {
    if (!t || t->count >= REPORT_MAX_ENTRIES) return;
    EvidenceEntry *e = &t->entries[t->count++];
    if (path)   strncpy(e->path,   path,   MAX_PATH - 1);
    if (name)   strncpy(e->name,   name,   sizeof(e->name) - 1);
    if (detail) strncpy(e->detail, detail, MAX_PATH - 1);
    if (reason) strncpy(e->reason, reason, MAX_DESCRIPTION - 1);
    e->status = status;

    switch (status) {
        case ENTRY_OK:      t->ok_count++;      break;
        case ENTRY_SKIPPED: t->skipped_count++; break;
        case ENTRY_WARN:    t->warn_count++;    break;
        case ENTRY_FLAGGED: t->flagged_count++; break;
    }
}

/* -----------------------------------------------
   CSV evidence file  (<report_stem>_<module>.csv)
   ----------------------------------------------- */
static void write_evidence_csv(const ScanReport *r, const EvidenceTable *t) {
    /* Build CSV path: replace .md extension with _<module>.csv */
    char csv_path[MAX_LOG_PATH];
    strncpy(csv_path, r->report_path, MAX_LOG_PATH - 1);
    char *dot = strrchr(csv_path, '.');
    if (dot) snprintf(dot, MAX_LOG_PATH - (int)(dot - csv_path),
                      "_%s.csv", t->module);
    else     snprintf(csv_path + strlen(csv_path),
                      MAX_LOG_PATH - strlen(csv_path) - 1,
                      "_%s.csv", t->module);

    FILE *fp = fopen(csv_path, "w");
    if (!fp) {
        LOG_ERR("cannot write CSV: %s (err=%lu)", csv_path, GetLastError());
        return;
    }

    /* Header */
    fprintf(fp, "status,name,detail,path,reason\r\n");

    for (int i = 0; i < t->count; i++) {
        const EvidenceEntry *e = &t->entries[i];
        /* Simple CSV quoting: wrap fields containing comma/quote/newline */
        fprintf(fp, "%s,\"%s\",\"%s\",\"%s\",\"%s\"\r\n",
                entry_status_str(e->status),
                e->name, e->detail, e->path, e->reason);
    }

    fclose(fp);
    LOG_INFO("CSV written: %s (%d entries)", csv_path, t->count);
}

/* -----------------------------------------------
   Markdown report
   ----------------------------------------------- */
static void write_md_alerts(FILE *fp, const ScanReport *r) {
    if (r->count == 0) {
        fprintf(fp, "> No alerts found. System appears clean.\n\n");
        return;
    }

    static const Severity  order[]  = { SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW };
    static const char     *labels[] = { "Critical", "High", "Medium", "Low" };

    for (int s = 0; s < 4; s++) {
        Severity sev = order[s];
        int found = 0;
        for (int i = 0; i < r->count && !found; i++)
            found = (r->alerts[i].severity == sev);
        if (!found) continue;

        fprintf(fp, "## %s Alerts\n\n", labels[s]);

        for (int i = 0; i < r->count; i++) {
            const Alert *a = &r->alerts[i];
            if (a->severity != sev) continue;

            char ts[32];
            ids_timestamp_str(a->timestamp, ts, sizeof(ts));

            fprintf(fp,
                "### [%s] %s\n\n"
                "| Field   | Value |\n"
                "|---------|-------|\n"
                "| Time    | %s |\n"
                "| Type    | %s |\n"
                "| Details | %s |\n",
                ids_severity_str(sev), ids_alert_type_str(a->type),
                ts, ids_alert_type_str(a->type), a->description);

            if (a->technique_id[0])   fprintf(fp, "| MITRE   | %s |\n", a->technique_id);
            if (a->file_path[0])      fprintf(fp, "| File    | %s |\n", a->file_path);
            if (a->source_ip[0])      fprintf(fp, "| Source  | %s:%lu |\n", a->source_ip, a->source_port);
            if (a->dest_ip[0])        fprintf(fp, "| Dest    | %s:%lu |\n", a->dest_ip,   a->dest_port);
            if (a->pid)               fprintf(fp, "| PID     | %lu (%s) |\n", a->pid, a->process_name);
            if (a->parent_process[0]) fprintf(fp, "| Parent  | %s |\n", a->parent_process);
            if (a->command_line[0])   fprintf(fp, "| CmdLine | %s |\n", a->command_line);
            if (a->rule_name[0])      fprintf(fp, "| Rule    | %s |\n", a->rule_name);
            fprintf(fp, "\n");
        }
    }
}

static void write_md_evidence(FILE *fp, const ScanReport *r) {
    for (int t = 0; t < r->table_count; t++) {
        const EvidenceTable *tbl = &r->tables[t];
        if (tbl->count == 0) continue;

        fprintf(fp,
            "## Evidence: %s\n\n"
            "Analyzed: %d  |  OK: %d  |  Skipped: %d  |  Flagged: %d\n\n"
            "| Status | Name | Detail | Reason |\n"
            "|--------|------|--------|--------|\n",
            tbl->module,
            tbl->count, tbl->ok_count, tbl->skipped_count, tbl->flagged_count);

        for (int i = 0; i < tbl->count; i++) {
            const EvidenceEntry *e = &tbl->entries[i];
            fprintf(fp, "| %s | %s | %s | %s |\n",
                    entry_status_str(e->status),
                    e->name[0]   ? e->name   : e->path,
                    e->detail[0] ? e->detail : "-",
                    e->reason[0] ? e->reason : "-");
        }
        fprintf(fp, "\n");
    }
}

static void write_md(const ScanReport *r) {
    FILE *fp = fopen(r->report_path, "w");
    if (!fp) {
        LOG_ERR("cannot write report: %s (err=%lu)", r->report_path, GetLastError());
        return;
    }

    char ts_start[32], ts_end[32];
    ids_timestamp_str(r->scan_start, ts_start, sizeof(ts_start));
    ids_timestamp_str(r->scan_end,   ts_end,   sizeof(ts_end));
    SevCount c = count_sev(r);

    fprintf(fp,
        "# Narsil Security Scan Report\n\n"
        "| Field        | Value |\n"
        "|--------------|-------|\n"
        "| Scan start   | %s |\n"
        "| Scan end     | %s |\n"
        "| Total alerts | %d |\n\n"
        "## Summary\n\n"
        "| Severity | Count |\n"
        "|----------|-------|\n"
        "| CRITICAL | %d |\n"
        "| HIGH     | %d |\n"
        "| MEDIUM   | %d |\n"
        "| LOW      | %d |\n\n",
        ts_start, ts_end, r->count,
        c.critical, c.high, c.medium, c.low);

    write_md_alerts(fp, r);
    write_md_evidence(fp, r);

    fclose(fp);
    LOG_INFO("report written: %s (%d alerts)", r->report_path, r->count);
}

/* -----------------------------------------------
   JSONL
   ----------------------------------------------- */
static void write_jsonl(const ScanReport *r) {
    FILE *fp = fopen(r->jsonl_path, "w");
    if (!fp) {
        LOG_ERR("cannot write JSONL: %s (err=%lu)", r->jsonl_path, GetLastError());
        return;
    }

    for (int i = 0; i < r->count; i++) {
        const Alert *a = &r->alerts[i];
        char ts[32];
        char e_desc[MAX_DESCRIPTION * 2];
        char e_proc[MAX_PATH * 2];
        char e_file[MAX_PATH * 2];
        char e_cmd[1024 * 2];

        ids_timestamp_str(a->timestamp, ts, sizeof(ts));
        narsil_json_escape(a->description,  e_desc, sizeof(e_desc));
        narsil_json_escape(a->process_name, e_proc, sizeof(e_proc));
        narsil_json_escape(a->file_path,    e_file, sizeof(e_file));
        narsil_json_escape(a->command_line, e_cmd,  sizeof(e_cmd));

        fprintf(fp,
            "{\"time\":\"%s\",\"sev\":\"%s\",\"type\":\"%s\","
            "\"src\":\"%s\",\"src_port\":%lu,"
            "\"dst\":\"%s\",\"dst_port\":%lu,"
            "\"pid\":%lu,\"proc\":\"%s\","
            "\"mitre\":\"%s\",\"rule\":\"%s\","
            "\"file\":\"%s\",\"cmdline\":\"%s\","
            "\"desc\":\"%s\"}\n",
            ts,
            ids_severity_str(a->severity),
            ids_alert_type_str(a->type),
            a->source_ip, a->source_port,
            a->dest_ip,   a->dest_port,
            a->pid,       e_proc,
            a->technique_id, a->rule_name,
            e_file, e_cmd, e_desc);
    }

    fclose(fp);
    LOG_INFO("JSONL written: %s (%d records)", r->jsonl_path, r->count);
}

/* -----------------------------------------------
   Finalise
   ----------------------------------------------- */
void report_write(ScanReport *r, IdsConfig *cfg) {
    (void)cfg;
    r->scan_end = time(NULL);
    SevCount c = count_sev(r);
    double elapsed = difftime(r->scan_end, r->scan_start);

    printf("\n==========================================\n");
    printf("  NARSIL SCAN COMPLETE\n");
    printf("==========================================\n");
    printf("  Total   : %d\n", r->count);
    printf("  Critical: %d\n", c.critical);
    printf("  High    : %d\n", c.high);
    printf("  Medium  : %d\n", c.medium);
    printf("  Low     : %d\n", c.low);
    printf("  Elapsed : %.0fs\n", elapsed);
    printf("==========================================\n\n");

    write_md(r);
    write_jsonl(r);

    /* Write CSV for every evidence table */
    for (int i = 0; i < r->table_count; i++)
        write_evidence_csv(r, &r->tables[i]);
}