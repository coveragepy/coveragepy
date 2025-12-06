/* Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0 */
/* For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt */

#ifndef _COVERAGE_SYSMON_H
#define _COVERAGE_SYSMON_H

#include "util.h"

/* The CodeInfo structure holds information about each code object we're tracking. */
typedef struct CodeInfo {
    BOOL tracing;
    PyObject * file_data;           /* Borrowed reference to the set in data dict */
    PyObject * byte_to_line;        /* Dict mapping byte offset to line number, owned */
    PyObject * branch_trails;       /* Dict for branch tracking, owned */
    PyObject * always_jumps;        /* Dict for always-jump offsets, owned */
} CodeInfo;

/* The CSysMonitor type. */
typedef struct CSysMonitor {
    PyObject_HEAD

    /* Python objects manipulated by the Collector class. */
    PyObject * data;                /* TTraceData dict */
    PyObject * should_trace;        /* TShouldTraceFn callback */
    PyObject * should_trace_cache;  /* Cache dict */
    PyObject * lock_data;           /* Lock function */
    PyObject * unlock_data;         /* Unlock function */
    PyObject * trace_arcs;          /* Boolean or None */
    PyObject * warn;                /* Warning function */

    /* C-only members */
    int myid;                       /* Tool ID for sys.monitoring */
    PyObject * code_infos;          /* Dict: id(code_object) -> CodeInfo struct */
    PyObject * code_objects;        /* List to keep code objects alive */
    BOOL sysmon_on;                 /* Is monitoring active? */
    PyObject * lock;                /* threading.Lock object */
    _Atomic BOOL activity;          /* Has there been any activity? */
    BOOL tracing_arcs;              /* Cached value from trace_arcs */
} CSysMonitor;

int CSysMonitor_intern_strings(void);

extern PyTypeObject CSysMonitorType;

#endif /* _COVERAGE_SYSMON_H */
