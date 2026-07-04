#ifndef REPORT_H
#define REPORT_H

#include "../include/ids.h"

#define REPORT_MAX_ALERTS  4096
#define REPORT_MAX_ENTRIES 8192   /* max rows in any evidence table */

/* -----------------------------------------------
   Evidence entry — one analyzed item.
   Used to build per-module "what we checked" tables.
   ----------------------------------------------- */
typedef enum {
    ENTRY_OK       = 0,   /* clean, no issues          */
    ENTRY_SKIPPED  = 1,   /* excluded (known FP, etc.) */
    ENTRY_WARN     = 2,   /* suspicious but not certain */
    ENTRY_FLAGGED  = 3,   /* confirmed issue            */
} EntryStatus;

typedef struct {
    char        path[MAX_PATH];       /* file or object path     */
    char        name[128];            /* short display name      */
    char        detail[MAX_PATH];     /* extra info (sig type, etc.) */
    char        reason[MAX_DESCRIPTION]; /* why flagged / skipped */
    EntryStatus status;
} EvidenceEntry;

/* -----------------------------------------------
   Evidence table — one per scan module
   ----------------------------------------------- */
typedef struct {
    char          module[32];                  /* e.g. "kernel_drivers" */
    EvidenceEntry entries[REPORT_MAX_ENTRIES];
    int           count;
    int           ok_count;
    int           skipped_count;
    int           warn_count;
    int           flagged_count;
} EvidenceTable;

/* -----------------------------------------------
   Scan report context
   Defined as 'struct ScanReport' to match the
   forward declaration in ids.h:
     typedef struct ScanReport ScanReport;
   ----------------------------------------------- */
struct ScanReport {
    Alert         alerts[REPORT_MAX_ALERTS];
    int           count;
    time_t        scan_start;
    time_t        scan_end;
    char          report_path[MAX_LOG_PATH];
    char          jsonl_path[MAX_LOG_PATH];

    /* Evidence tables — one slot per module */
    EvidenceTable tables[16];
    int           table_count;
};

/* Lifecycle */
ScanReport   *report_create(const char *report_path, const char *jsonl_path);
void          report_free(ScanReport *r);

/* Alerts */
void          report_add(ScanReport *r, const Alert *a);

/* Evidence tables */
EvidenceTable *report_table_begin(ScanReport *r, const char *module);
void           report_table_add(EvidenceTable *t, const char *path,
                                const char *name, const char *detail,
                                EntryStatus status, const char *reason);

/* Finalise */
void          report_write(ScanReport *r, IdsConfig *cfg);

#endif /* REPORT_H */