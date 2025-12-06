/* Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0 */
/* For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt */

/* C-based sys.monitoring tracer for coverage.py (PEP 669). */

#include "util.h"
#include "structmember.h"
#include "sysmon.h"

/* Interned strings */
static PyObject *str_co_lines;
static PyObject *str_get;
static PyObject *str_DISABLE;
static PyObject *str_use_tool_id;
static PyObject *str_free_tool_id;
static PyObject *str_register_callback;
static PyObject *str_set_events;
static PyObject *str_set_local_events;
static PyObject *str_restart_events;
static PyObject *str_events;
static PyObject *str_PY_START;
static PyObject *str_PY_RETURN;
static PyObject *str_PY_RESUME;
static PyObject *str_LINE;
static PyObject *str_BRANCH_RIGHT;
static PyObject *str_BRANCH_LEFT;
static PyObject *str_monitoring;

int
CSysMonitor_intern_strings(void)
{
    int ret = RET_ERROR;

#define INTERN_STRING(v, s)                     \
    v = PyUnicode_InternFromString(s);          \
    if (v == NULL) {                            \
        goto error;                             \
    }

    INTERN_STRING(str_co_lines, "co_lines")
    INTERN_STRING(str_get, "get")
    INTERN_STRING(str_DISABLE, "DISABLE")
    INTERN_STRING(str_use_tool_id, "use_tool_id")
    INTERN_STRING(str_free_tool_id, "free_tool_id")
    INTERN_STRING(str_register_callback, "register_callback")
    INTERN_STRING(str_set_events, "set_events")
    INTERN_STRING(str_set_local_events, "set_local_events")
    INTERN_STRING(str_restart_events, "restart_events")
    INTERN_STRING(str_events, "events")
    INTERN_STRING(str_PY_START, "PY_START")
    INTERN_STRING(str_PY_RETURN, "PY_RETURN")
    INTERN_STRING(str_PY_RESUME, "PY_RESUME")
    INTERN_STRING(str_LINE, "LINE")
    INTERN_STRING(str_BRANCH_RIGHT, "BRANCH_RIGHT")
    INTERN_STRING(str_BRANCH_LEFT, "BRANCH_LEFT")
    INTERN_STRING(str_monitoring, "monitoring")

    ret = RET_OK;

error:
    return ret;
}

/* Helper to get sys.monitoring module */
static PyObject *
get_monitoring_module(void)
{
    PyObject *sys_module = PyImport_ImportModule("sys");
    if (sys_module == NULL) {
        return NULL;
    }

    PyObject *monitoring = PyObject_GetAttr(sys_module, str_monitoring);
    Py_DECREF(sys_module);
    return monitoring;
}

/* Helper to create a CodeInfo capsule */
static void
CodeInfo_dealloc(PyObject *capsule)
{
    CodeInfo *info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
    if (info != NULL) {
        Py_XDECREF(info->byte_to_line);
        Py_XDECREF(info->branch_trails);
        Py_XDECREF(info->always_jumps);
        PyMem_Free(info);
    }
}

static PyObject *
CodeInfo_new(BOOL tracing, PyObject *file_data, PyObject *byte_to_line)
{
    CodeInfo *info = PyMem_Malloc(sizeof(CodeInfo));
    if (info == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    info->tracing = tracing;
    info->file_data = file_data;  /* Borrowed reference */
    info->byte_to_line = byte_to_line;
    Py_XINCREF(byte_to_line);
    info->branch_trails = PyDict_New();
    info->always_jumps = PyDict_New();

    if (info->branch_trails == NULL || info->always_jumps == NULL) {
        Py_XDECREF(info->branch_trails);
        Py_XDECREF(info->always_jumps);
        Py_XDECREF(info->byte_to_line);
        PyMem_Free(info);
        return NULL;
    }

    return PyCapsule_New(info, "CodeInfo", CodeInfo_dealloc);
}

/* Helper: bytes_to_lines - create dict mapping byte offset to line number */
static PyObject *
bytes_to_lines(PyCodeObject *code)
{
    PyObject *b2l = PyDict_New();
    if (b2l == NULL) {
        return NULL;
    }

    /* Call code.co_lines() to get the line number table */
    PyObject *co_lines_iter = PyObject_CallMethodNoArgs((PyObject *)code, str_co_lines);
    if (co_lines_iter == NULL) {
        Py_DECREF(b2l);
        return NULL;
    }

    PyObject *item;
    while ((item = PyIter_Next(co_lines_iter)) != NULL) {
        /* Each item is (bstart, bend, lineno) */
        PyObject *bstart_obj, *bend_obj, *lineno_obj;
        if (!PyArg_ParseTuple(item, "OOO", &bstart_obj, &bend_obj, &lineno_obj)) {
            Py_DECREF(item);
            Py_DECREF(co_lines_iter);
            Py_DECREF(b2l);
            return NULL;
        }

        /* Skip if lineno is None */
        if (lineno_obj != Py_None) {
            long bstart = PyLong_AsLong(bstart_obj);
            long bend = PyLong_AsLong(bend_obj);

            if (bstart == -1 || bend == -1) {
                if (PyErr_Occurred()) {
                    Py_DECREF(item);
                    Py_DECREF(co_lines_iter);
                    Py_DECREF(b2l);
                    return NULL;
                }
            }

            /* Map each offset in range [bstart, bend) with step 2 */
            for (long boffset = bstart; boffset < bend; boffset += 2) {
                PyObject *offset_key = PyLong_FromLong(boffset);
                if (offset_key == NULL) {
                    Py_DECREF(item);
                    Py_DECREF(co_lines_iter);
                    Py_DECREF(b2l);
                    return NULL;
                }

                if (PyDict_SetItem(b2l, offset_key, lineno_obj) < 0) {
                    Py_DECREF(offset_key);
                    Py_DECREF(item);
                    Py_DECREF(co_lines_iter);
                    Py_DECREF(b2l);
                    return NULL;
                }
                Py_DECREF(offset_key);
            }
        }

        Py_DECREF(item);
    }

    Py_DECREF(co_lines_iter);

    if (PyErr_Occurred()) {
        Py_DECREF(b2l);
        return NULL;
    }

    return b2l;
}

/* Helper to call Python functions for branch_trails and always_jumps */
static int
populate_branch_info(CodeInfo *info, PyCodeObject *code, PyObject *multiline_map)
{
    /* Import coverage.bytecode module */
    PyObject *bytecode_module = PyImport_ImportModule("coverage.bytecode");
    if (bytecode_module == NULL) {
        return RET_ERROR;
    }

    /* Call branch_trails(code, multiline_map=multiline_map) */
    PyObject *branch_trails_func = PyObject_GetAttrString(bytecode_module, "branch_trails");
    if (branch_trails_func == NULL) {
        Py_DECREF(bytecode_module);
        return RET_ERROR;
    }

    PyObject *args = PyTuple_Pack(1, code);
    PyObject *kwargs = PyDict_New();
    if (args == NULL || kwargs == NULL) {
        Py_XDECREF(args);
        Py_XDECREF(kwargs);
        Py_DECREF(branch_trails_func);
        Py_DECREF(bytecode_module);
        return RET_ERROR;
    }

    PyDict_SetItemString(kwargs, "multiline_map", multiline_map);

    PyObject *trails = PyObject_Call(branch_trails_func, args, kwargs);
    Py_DECREF(args);
    Py_DECREF(kwargs);
    Py_DECREF(branch_trails_func);

    if (trails == NULL) {
        Py_DECREF(bytecode_module);
        return RET_ERROR;
    }

    Py_DECREF(info->branch_trails);
    info->branch_trails = trails;

    /* Call always_jumps(code) */
    PyObject *always_jumps_func = PyObject_GetAttrString(bytecode_module, "always_jumps");
    Py_DECREF(bytecode_module);

    if (always_jumps_func == NULL) {
        return RET_ERROR;
    }

    PyObject *jumps = PyObject_CallFunctionObjArgs(always_jumps_func, code, NULL);
    Py_DECREF(always_jumps_func);

    if (jumps == NULL) {
        return RET_ERROR;
    }

    Py_DECREF(info->always_jumps);
    info->always_jumps = jumps;

    return RET_OK;
}

/* Helper to get multiline_map from PythonParser */
static PyObject *
get_multiline_map(const char *filename)
{
    PyObject *parser_module = PyImport_ImportModule("coverage.parser");
    if (parser_module == NULL) {
        return NULL;
    }

    PyObject *parser_class = PyObject_GetAttrString(parser_module, "PythonParser");
    Py_DECREF(parser_module);
    if (parser_class == NULL) {
        return NULL;
    }

    /* Create parser with filename */
    PyObject *kwargs = PyDict_New();
    if (kwargs == NULL) {
        Py_DECREF(parser_class);
        return NULL;
    }

    PyObject *filename_str = PyUnicode_FromString(filename);
    if (filename_str == NULL) {
        Py_DECREF(kwargs);
        Py_DECREF(parser_class);
        return NULL;
    }

    PyDict_SetItemString(kwargs, "filename", filename_str);
    Py_DECREF(filename_str);

    PyObject *parser = PyObject_Call(parser_class, PyTuple_New(0), kwargs);
    Py_DECREF(kwargs);
    Py_DECREF(parser_class);

    if (parser == NULL) {
        /* Handle NotPython or NoSource exceptions by returning empty dict */
        if (PyErr_Occurred()) {
            PyObject *exc_type, *exc_value, *exc_tb;
            PyErr_Fetch(&exc_type, &exc_value, &exc_tb);

            /* Check if it's NotPython or NoSource */
            PyObject *exceptions_module = PyImport_ImportModule("coverage.exceptions");
            if (exceptions_module != NULL) {
                PyObject *NotPython = PyObject_GetAttrString(exceptions_module, "NotPython");
                PyObject *NoSource = PyObject_GetAttrString(exceptions_module, "NoSource");
                Py_DECREF(exceptions_module);

                int is_expected = 0;
                if (NotPython != NULL && PyErr_GivenExceptionMatches(exc_type, NotPython)) {
                    is_expected = 1;
                }
                if (NoSource != NULL && PyErr_GivenExceptionMatches(exc_type, NoSource)) {
                    is_expected = 1;
                }

                Py_XDECREF(NotPython);
                Py_XDECREF(NoSource);

                if (is_expected) {
                    Py_XDECREF(exc_type);
                    Py_XDECREF(exc_value);
                    Py_XDECREF(exc_tb);
                    return PyDict_New();
                }
            }

            PyErr_Restore(exc_type, exc_value, exc_tb);
        }
        return NULL;
    }

    /* Call parse_source() */
    PyObject *result = PyObject_CallMethod(parser, "parse_source", NULL);
    if (result == NULL) {
        Py_DECREF(parser);
        /* Same exception handling as above */
        if (PyErr_Occurred()) {
            PyObject *exc_type, *exc_value, *exc_tb;
            PyErr_Fetch(&exc_type, &exc_value, &exc_tb);

            PyObject *exceptions_module = PyImport_ImportModule("coverage.exceptions");
            if (exceptions_module != NULL) {
                PyObject *NotPython = PyObject_GetAttrString(exceptions_module, "NotPython");
                PyObject *NoSource = PyObject_GetAttrString(exceptions_module, "NoSource");
                Py_DECREF(exceptions_module);

                int is_expected = 0;
                if (NotPython != NULL && PyErr_GivenExceptionMatches(exc_type, NotPython)) {
                    is_expected = 1;
                }
                if (NoSource != NULL && PyErr_GivenExceptionMatches(exc_type, NoSource)) {
                    is_expected = 1;
                }

                Py_XDECREF(NotPython);
                Py_XDECREF(NoSource);

                if (is_expected) {
                    Py_XDECREF(exc_type);
                    Py_XDECREF(exc_value);
                    Py_XDECREF(exc_tb);
                    return PyDict_New();
                }
            }

            PyErr_Restore(exc_type, exc_value, exc_tb);
        }
        return NULL;
    }
    Py_DECREF(result);

    /* Get multiline_map attribute */
    PyObject *multiline_map = PyObject_GetAttrString(parser, "multiline_map");
    Py_DECREF(parser);

    return multiline_map;
}

/*
 * CSysMonitor initialization and deallocation
 */

static int
CSysMonitor_init(CSysMonitor *self, PyObject *args, PyObject *kwds)
{
    int tool_id = 1;  /* Default tool_id */

    static char *kwlist[] = {"tool_id", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &tool_id)) {
        return RET_ERROR;
    }

    self->myid = tool_id;
    self->sysmon_on = FALSE;
    atomic_store(&self->activity, FALSE);
    self->tracing_arcs = FALSE;

    /* Create code_infos dict */
    self->code_infos = PyDict_New();
    if (self->code_infos == NULL) {
        return RET_ERROR;
    }

    /* Create code_objects list */
    self->code_objects = PyList_New(0);
    if (self->code_objects == NULL) {
        return RET_ERROR;
    }

    /* Create threading lock */
    PyObject *threading = PyImport_ImportModule("threading");
    if (threading == NULL) {
        return RET_ERROR;
    }

    self->lock = PyObject_CallMethod(threading, "Lock", NULL);
    Py_DECREF(threading);

    if (self->lock == NULL) {
        return RET_ERROR;
    }

    return RET_OK;
}

static void
CSysMonitor_dealloc(CSysMonitor *self)
{
    Py_XDECREF(self->data);
    Py_XDECREF(self->should_trace);
    Py_XDECREF(self->should_trace_cache);
    Py_XDECREF(self->lock_data);
    Py_XDECREF(self->unlock_data);
    Py_XDECREF(self->trace_arcs);
    Py_XDECREF(self->warn);
    Py_XDECREF(self->code_infos);
    Py_XDECREF(self->code_objects);
    Py_XDECREF(self->lock);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*
 * Event handler callbacks
 */

/* PY_START event handler */
static PyObject *
CSysMonitor_py_start(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code;
    int instruction_offset;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &instruction_offset)) {
        return NULL;
    }

    atomic_store(&self->activity, TRUE);

    /* Skip __annotate__ functions */
    if (strcmp(PyUnicode_AsUTF8(code->co_name), "__annotate__") == 0) {
        PyObject *monitoring = get_monitoring_module();
        if (monitoring == NULL) {
            return NULL;
        }
        PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
        Py_DECREF(monitoring);
        return disable;
    }

    /* Check if we already have info for this code object */
    PyObject *code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        return NULL;
    }

    PyObject *capsule = PyDict_GetItem(self->code_infos, code_id);
    CodeInfo *code_info = NULL;
    BOOL tracing_code = FALSE;
    PyObject *file_data = NULL;

    if (capsule != NULL) {
        code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL) {
            tracing_code = code_info->tracing;
            file_data = code_info->file_data;
        }
    }

    if (code_info == NULL) {
        /* Need to determine if we should trace this file */
        PyObject *filename = code->co_filename;
        PyObject *disp = PyDict_GetItem(self->should_trace_cache, filename);

        if (disp == NULL) {
            /* Call should_trace(filename, frame) */
            PyObject *frame = NULL;
            PyFrameObject *current_frame = PyEval_GetFrame();
            if (current_frame != NULL) {
                Py_INCREF(current_frame);
                frame = (PyObject *)current_frame;
            }

            disp = PyObject_CallFunctionObjArgs(self->should_trace, filename, frame, NULL);
            Py_XDECREF(frame);

            if (disp == NULL) {
                Py_DECREF(code_id);
                return NULL;
            }

            if (PyDict_SetItem(self->should_trace_cache, filename, disp) < 0) {
                Py_DECREF(disp);
                Py_DECREF(code_id);
                return NULL;
            }
            Py_DECREF(disp);
            disp = PyDict_GetItem(self->should_trace_cache, filename);
        }

        /* Check if we should trace */
        PyObject *trace_attr = PyObject_GetAttrString(disp, "trace");
        if (trace_attr == NULL) {
            Py_DECREF(code_id);
            return NULL;
        }

        tracing_code = (trace_attr == Py_True);
        Py_DECREF(trace_attr);

        PyObject *byte_to_line = NULL;
        if (tracing_code) {
            PyObject *source_filename = PyObject_GetAttrString(disp, "source_filename");
            if (source_filename == NULL) {
                Py_DECREF(code_id);
                return NULL;
            }

            /* Lock data and get/create file_data set */
            PyObject *lock_result = PyObject_CallNoArgs(self->lock_data);
            if (lock_result == NULL) {
                Py_DECREF(source_filename);
                Py_DECREF(code_id);
                return NULL;
            }
            Py_DECREF(lock_result);

            file_data = PyDict_GetItem(self->data, source_filename);
            if (file_data == NULL) {
                file_data = PySet_New(NULL);
                if (file_data == NULL) {
                    PyObject_CallNoArgs(self->unlock_data);
                    Py_DECREF(source_filename);
                    Py_DECREF(code_id);
                    return NULL;
                }

                if (PyDict_SetItem(self->data, source_filename, file_data) < 0) {
                    Py_DECREF(file_data);
                    PyObject_CallNoArgs(self->unlock_data);
                    Py_DECREF(source_filename);
                    Py_DECREF(code_id);
                    return NULL;
                }
                Py_DECREF(file_data);
                file_data = PyDict_GetItem(self->data, source_filename);
            }

            PyObject *unlock_result = PyObject_CallNoArgs(self->unlock_data);
            if (unlock_result == NULL) {
                Py_DECREF(source_filename);
                Py_DECREF(code_id);
                return NULL;
            }
            Py_DECREF(unlock_result);
            Py_DECREF(source_filename);

            /* Create byte_to_line mapping */
            byte_to_line = bytes_to_lines(code);
            if (byte_to_line == NULL) {
                Py_DECREF(code_id);
                return NULL;
            }
        }

        /* Create CodeInfo */
        capsule = CodeInfo_new(tracing_code, file_data, byte_to_line);
        Py_XDECREF(byte_to_line);

        if (capsule == NULL) {
            Py_DECREF(code_id);
            return NULL;
        }

        if (PyDict_SetItem(self->code_infos, code_id, capsule) < 0) {
            Py_DECREF(capsule);
            Py_DECREF(code_id);
            return NULL;
        }
        Py_DECREF(capsule);

        /* Keep code object alive */
        if (PyList_Append(self->code_objects, (PyObject *)code) < 0) {
            Py_DECREF(code_id);
            return NULL;
        }

        code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");

        /* Enable local events for this code if tracing */
        if (tracing_code) {
            PyObject *lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
            if (lock_result == NULL) {
                Py_DECREF(code_id);
                return NULL;
            }
            Py_DECREF(lock_result);

            if (self->sysmon_on) {
                PyObject *monitoring = get_monitoring_module();
                if (monitoring == NULL) {
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    Py_DECREF(code_id);
                    return NULL;
                }

                PyObject *events_obj = PyObject_GetAttr(monitoring, str_events);
                if (events_obj == NULL) {
                    Py_DECREF(monitoring);
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    Py_DECREF(code_id);
                    return NULL;
                }

                /* Build local_events mask */
                PyObject *py_return = PyObject_GetAttr(events_obj, str_PY_RETURN);
                PyObject *py_resume = PyObject_GetAttr(events_obj, str_PY_RESUME);
                PyObject *line = PyObject_GetAttr(events_obj, str_LINE);

                if (py_return == NULL || py_resume == NULL || line == NULL) {
                    Py_XDECREF(py_return);
                    Py_XDECREF(py_resume);
                    Py_XDECREF(line);
                    Py_DECREF(events_obj);
                    Py_DECREF(monitoring);
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    Py_DECREF(code_id);
                    return NULL;
                }

                long local_events = PyLong_AsLong(py_return) | PyLong_AsLong(py_resume) | PyLong_AsLong(line);
                Py_DECREF(py_return);
                Py_DECREF(py_resume);
                Py_DECREF(line);

                /* Add branch events if tracing arcs */
                if (self->tracing_arcs) {
                    PyObject *branch_right = PyObject_GetAttr(events_obj, str_BRANCH_RIGHT);
                    PyObject *branch_left = PyObject_GetAttr(events_obj, str_BRANCH_LEFT);

                    if (branch_right != NULL && branch_left != NULL) {
                        local_events |= PyLong_AsLong(branch_right) | PyLong_AsLong(branch_left);
                    }

                    Py_XDECREF(branch_right);
                    Py_XDECREF(branch_left);
                }

                Py_DECREF(events_obj);

                /* Call sys.monitoring.set_local_events(myid, code, local_events) */
                PyObject *events_long = PyLong_FromLong(local_events);
                PyObject *myid_long = PyLong_FromLong(self->myid);

                if (events_long != NULL && myid_long != NULL) {
                    PyObject *set_result = PyObject_CallMethod(monitoring, "set_local_events", "OOO",
                                       myid_long, code, events_long);
                    Py_XDECREF(set_result);
                }

                Py_XDECREF(events_long);
                Py_XDECREF(myid_long);
                Py_DECREF(monitoring);
            }

            PyObject *exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
            Py_XDECREF(exit_result);
        }
    }

    Py_DECREF(code_id);

    /* Return DISABLE */
    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        return NULL;
    }
    PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
    Py_DECREF(monitoring);
    return disable;
}

/* LINE event handler for line coverage */
static PyObject *
CSysMonitor_line_lines(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code;
    int line_number;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &line_number)) {
        return NULL;
    }

    PyObject *code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        return NULL;
    }

    PyObject *capsule = PyDict_GetItem(self->code_infos, code_id);
    Py_DECREF(code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->file_data != NULL) {
            PyObject *line_obj = PyLong_FromLong(line_number);
            if (line_obj != NULL) {
                PySet_Add(code_info->file_data, line_obj);
                Py_DECREF(line_obj);
            }
        }
    }

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        return NULL;
    }
    PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
    Py_DECREF(monitoring);
    return disable;
}

/* LINE event handler for arc coverage */
static PyObject *
CSysMonitor_line_arcs(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code;
    int line_number;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &line_number)) {
        return NULL;
    }

    PyObject *code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        return NULL;
    }

    PyObject *capsule = PyDict_GetItem(self->code_infos, code_id);
    Py_DECREF(code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->file_data != NULL) {
            /* Add (line_number, line_number) arc */
            PyObject *arc = PyTuple_Pack(2, PyLong_FromLong(line_number), PyLong_FromLong(line_number));
            if (arc != NULL) {
                PySet_Add(code_info->file_data, arc);
                Py_DECREF(arc);
            }
        }
    }

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        return NULL;
    }
    PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
    Py_DECREF(monitoring);
    return disable;
}

/* PY_RETURN event handler */
static PyObject *
CSysMonitor_py_return(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code;
    int instruction_offset;
    PyObject *retval;

    if (!PyArg_ParseTuple(args, "O!iO", &PyCode_Type, &code, &instruction_offset, &retval)) {
        return NULL;
    }

    PyObject *code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        return NULL;
    }

    PyObject *capsule = PyDict_GetItem(self->code_infos, code_id);
    Py_DECREF(code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->byte_to_line != NULL) {
            PyObject *offset_key = PyLong_FromLong(instruction_offset);
            if (offset_key != NULL) {
                PyObject *last_line = PyDict_GetItem(code_info->byte_to_line, offset_key);
                Py_DECREF(offset_key);

                if (last_line != NULL) {
                    long last_line_num = PyLong_AsLong(last_line);
                    long first_line = code->co_firstlineno;

                    /* Add (last_line, -first_line) arc */
                    PyObject *arc = PyTuple_Pack(2,
                                                PyLong_FromLong(last_line_num),
                                                PyLong_FromLong(-first_line));
                    if (arc != NULL) {
                        PySet_Add(code_info->file_data, arc);
                        Py_DECREF(arc);
                    }
                }
            }
        }
    }

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        return NULL;
    }
    PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
    Py_DECREF(monitoring);
    return disable;
}

/* BRANCH event handler (both BRANCH_RIGHT and BRANCH_LEFT) */
static PyObject *
CSysMonitor_branch_either(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code;
    int instruction_offset;
    int destination_offset;

    if (!PyArg_ParseTuple(args, "O!ii", &PyCode_Type, &code, &instruction_offset, &destination_offset)) {
        return NULL;
    }

    PyObject *code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        return NULL;
    }

    PyObject *capsule = PyDict_GetItem(self->code_infos, code_id);
    Py_DECREF(code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL) {
            /* Populate branch_trails if not done yet */
            if (PyDict_Size(code_info->branch_trails) == 0) {
                const char *filename = PyUnicode_AsUTF8(code->co_filename);
                if (filename != NULL) {
                    PyObject *multiline_map = get_multiline_map(filename);
                    if (multiline_map != NULL) {
                        populate_branch_info(code_info, code, multiline_map);
                        Py_DECREF(multiline_map);
                    } else {
                        /* Clear error and continue with empty multiline_map */
                        PyErr_Clear();
                        PyObject *empty_map = PyDict_New();
                        if (empty_map != NULL) {
                            populate_branch_info(code_info, code, empty_map);
                            Py_DECREF(empty_map);
                        }
                    }
                }
            }

            BOOL added_arc = FALSE;

            /* Re-map destination through always_jumps */
            PyObject *dest_set = PySet_New(NULL);
            if (dest_set != NULL) {
                PyObject *dest_obj = PyLong_FromLong(destination_offset);
                if (dest_obj != NULL) {
                    PySet_Add(dest_set, dest_obj);

                    PyObject *current_obj = dest_obj;

                    while (1) {
                        PyObject *next_dest = PyDict_GetItem(code_info->always_jumps, current_obj);
                        if (next_dest == NULL) {
                            break;
                        }

                        PySet_Add(dest_set, next_dest);
                        current_obj = next_dest;
                    }

                    Py_DECREF(dest_obj);
                }

                /* Look up branch_trails[instruction_offset] */
                PyObject *offset_key = PyLong_FromLong(instruction_offset);
                if (offset_key != NULL) {
                    PyObject *dest_info = PyDict_GetItem(code_info->branch_trails, offset_key);
                    Py_DECREF(offset_key);

                    if (dest_info != NULL && PyDict_Check(dest_info)) {
                        /* Iterate over dest_info items */
                        PyObject *arc, *offsets;
                        Py_ssize_t pos = 0;

                        while (PyDict_Next(dest_info, &pos, &arc, &offsets)) {
                            if (arc == Py_None) {
                                continue;
                            }

                            /* Check if any offset in offsets intersects with dest_set */
                            if (PySet_Check(offsets)) {
                                PyObject *intersection = PyNumber_And(dest_set, offsets);
                                if (intersection != NULL) {
                                    Py_ssize_t size = PySet_Size(intersection);
                                    Py_DECREF(intersection);

                                    if (size > 0) {
                                        PySet_Add(code_info->file_data, arc);
                                        added_arc = TRUE;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                Py_DECREF(dest_set);
            }

            /* If no arc was added, try direct line-to-line mapping */
            if (!added_arc && code_info->byte_to_line != NULL) {
                PyObject *offset_key = PyLong_FromLong(instruction_offset);
                PyObject *dest_key = PyLong_FromLong(destination_offset);

                if (offset_key != NULL && dest_key != NULL) {
                    PyObject *l1 = PyDict_GetItem(code_info->byte_to_line, offset_key);
                    PyObject *l2 = PyDict_GetItem(code_info->byte_to_line, dest_key);

                    if (l1 != NULL && l2 != NULL) {
                        long line1 = PyLong_AsLong(l1);
                        long line2 = PyLong_AsLong(l2);

                        if (line1 != line2) {
                            PyObject *arc = PyTuple_Pack(2, l1, l2);
                            if (arc != NULL) {
                                PySet_Add(code_info->file_data, arc);
                                Py_DECREF(arc);
                            }
                        }
                    }
                }

                Py_XDECREF(offset_key);
                Py_XDECREF(dest_key);
            }
        }
    }

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        return NULL;
    }
    PyObject *disable = PyObject_GetAttr(monitoring, str_DISABLE);
    Py_DECREF(monitoring);
    return disable;
}

/*
 * Management methods
 */

static PyObject *
CSysMonitor_start(CSysMonitor *self, PyObject *args_unused)
{
    PyObject *lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
    if (lock_result == NULL) {
        return NULL;
    }
    Py_DECREF(lock_result);

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }

    /* use_tool_id(myid, "coverage.py") */
    PyObject *myid_obj = PyLong_FromLong(self->myid);
    if (myid_obj == NULL) {
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }

    PyObject *name = PyUnicode_FromString("coverage.py");
    PyObject *result = PyObject_CallMethod(monitoring, "use_tool_id", "OO", myid_obj, name);
    Py_DECREF(name);

    if (result == NULL) {
        Py_DECREF(myid_obj);
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }
    Py_DECREF(result);

    /* Get events object */
    PyObject *events_obj = PyObject_GetAttr(monitoring, str_events);
    if (events_obj == NULL) {
        Py_DECREF(myid_obj);
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }

    /* Register callbacks */
    PyObject *py_start_event = PyObject_GetAttr(events_obj, str_PY_START);
    if (py_start_event == NULL) {
        Py_DECREF(events_obj);
        Py_DECREF(myid_obj);
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }

    /* Set initial events to PY_START */
    result = PyObject_CallMethod(monitoring, "set_events", "OO", myid_obj, py_start_event);

    if (result == NULL) {
        Py_DECREF(py_start_event);
        Py_DECREF(events_obj);
        Py_DECREF(myid_obj);
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }
    Py_DECREF(result);

    /* Register PY_START callback */
    PyObject *callback = PyObject_GetAttrString((PyObject *)self, "sysmon_py_start");
    result = PyObject_CallMethod(monitoring, "register_callback", "OOO", myid_obj, py_start_event, callback);
    Py_DECREF(py_start_event);
    Py_DECREF(callback);

    if (result == NULL) {
        Py_DECREF(events_obj);
        Py_DECREF(myid_obj);
        Py_DECREF(monitoring);
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }
    Py_DECREF(result);

    /* Determine which LINE callback to use */
    self->tracing_arcs = (self->trace_arcs != NULL && self->trace_arcs != Py_None && PyObject_IsTrue(self->trace_arcs));

    PyObject *line_event = PyObject_GetAttr(events_obj, str_LINE);
    if (line_event != NULL) {
        const char *line_callback_name = self->tracing_arcs ? "sysmon_line_arcs" : "sysmon_line_lines";
        callback = PyObject_GetAttrString((PyObject *)self, line_callback_name);
        result = PyObject_CallMethod(monitoring, "register_callback", "OOO", myid_obj, line_event, callback);
        Py_DECREF(callback);
        Py_XDECREF(result);
        Py_DECREF(line_event);
    }

    /* Register PY_RETURN if tracing arcs */
    if (self->tracing_arcs) {
        PyObject *py_return_event = PyObject_GetAttr(events_obj, str_PY_RETURN);
        if (py_return_event != NULL) {
            callback = PyObject_GetAttrString((PyObject *)self, "sysmon_py_return");
            result = PyObject_CallMethod(monitoring, "register_callback", "OOO", myid_obj, py_return_event, callback);
            Py_DECREF(callback);
            Py_XDECREF(result);
            Py_DECREF(py_return_event);
        }

        /* Register BRANCH events */
        PyObject *branch_right = PyObject_GetAttr(events_obj, str_BRANCH_RIGHT);
        PyObject *branch_left = PyObject_GetAttr(events_obj, str_BRANCH_LEFT);

        if (branch_right != NULL && branch_left != NULL) {
            callback = PyObject_GetAttrString((PyObject *)self, "sysmon_branch_either");

            result = PyObject_CallMethod(monitoring, "register_callback", "OOO", myid_obj, branch_right, callback);
            Py_XDECREF(result);

            result = PyObject_CallMethod(monitoring, "register_callback", "OOO", myid_obj, branch_left, callback);
            Py_XDECREF(result);

            Py_DECREF(callback);
        }

        Py_XDECREF(branch_right);
        Py_XDECREF(branch_left);
    }

    Py_DECREF(events_obj);
    Py_DECREF(myid_obj);

    /* Call restart_events() */
    result = PyObject_CallMethod(monitoring, "restart_events", NULL);
    Py_XDECREF(result);

    Py_DECREF(monitoring);

    self->sysmon_on = TRUE;

    PyObject *exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
    Py_XDECREF(exit_result);

    Py_RETURN_NONE;
}

static PyObject *
CSysMonitor_stop(CSysMonitor *self, PyObject *args_unused)
{
    PyObject *lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
    if (lock_result == NULL) {
        return NULL;
    }
    Py_DECREF(lock_result);

    if (!self->sysmon_on) {
        PyObject *exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        Py_XDECREF(exit_result);
        Py_RETURN_NONE;
    }

    PyObject *monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        return NULL;
    }

    /* set_events(myid, 0) */
    PyObject *myid_obj = PyLong_FromLong(self->myid);
    if (myid_obj != NULL) {
        PyObject *result = PyObject_CallMethod(monitoring, "set_events", "Oi", myid_obj, 0);
        Py_XDECREF(result);
        Py_DECREF(myid_obj);
    }

    self->sysmon_on = FALSE;

    /* free_tool_id(myid) */
    myid_obj = PyLong_FromLong(self->myid);
    if (myid_obj != NULL) {
        PyObject *result = PyObject_CallMethod(monitoring, "free_tool_id", "O", myid_obj);
        Py_XDECREF(result);
        Py_DECREF(myid_obj);
    }

    Py_DECREF(monitoring);

    PyObject *exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
    Py_XDECREF(exit_result);

    Py_RETURN_NONE;
}

static PyObject *
CSysMonitor_post_fork(CSysMonitor *self, PyObject *args_unused)
{
    return CSysMonitor_stop(self, args_unused);
}

static PyObject *
CSysMonitor_activity(CSysMonitor *self, PyObject *args_unused)
{
    if (atomic_load(&self->activity)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
CSysMonitor_reset_activity(CSysMonitor *self, PyObject *args_unused)
{
    atomic_store(&self->activity, FALSE);
    Py_RETURN_NONE;
}

static PyObject *
CSysMonitor_get_stats(CSysMonitor *self, PyObject *args_unused)
{
    Py_RETURN_NONE;
}

/*
 * Python interface
 */

static PyMemberDef
CSysMonitor_members[] = {
    { "data", T_OBJECT, offsetof(CSysMonitor, data), 0,
            PyDoc_STR("The raw dictionary of trace data.") },

    { "should_trace", T_OBJECT, offsetof(CSysMonitor, should_trace), 0,
            PyDoc_STR("Function indicating whether to trace a file.") },

    { "should_trace_cache", T_OBJECT, offsetof(CSysMonitor, should_trace_cache), 0,
            PyDoc_STR("Dictionary caching should_trace results.") },

    { "trace_arcs", T_OBJECT, offsetof(CSysMonitor, trace_arcs), 0,
            PyDoc_STR("Should we trace arcs, or just lines?") },

    { "lock_data", T_OBJECT, offsetof(CSysMonitor, lock_data), 0,
            PyDoc_STR("Function for locking access to self.data.") },

    { "unlock_data", T_OBJECT, offsetof(CSysMonitor, unlock_data), 0,
            PyDoc_STR("Function for unlocking access to self.data.") },

    { "warn", T_OBJECT, offsetof(CSysMonitor, warn), 0,
            PyDoc_STR("Function for issuing warnings.") },

    { NULL }
};

static PyMethodDef
CSysMonitor_methods[] = {
    { "start", (PyCFunction) CSysMonitor_start, METH_NOARGS,
            PyDoc_STR("Start the tracer") },

    { "stop", (PyCFunction) CSysMonitor_stop, METH_NOARGS,
            PyDoc_STR("Stop the tracer") },

    { "post_fork", (PyCFunction) CSysMonitor_post_fork, METH_NOARGS,
            PyDoc_STR("Handle post-fork cleanup") },

    { "activity", (PyCFunction) CSysMonitor_activity, METH_NOARGS,
            PyDoc_STR("Has there been any activity?") },

    { "reset_activity", (PyCFunction) CSysMonitor_reset_activity, METH_NOARGS,
            PyDoc_STR("Reset the activity flag") },

    { "get_stats", (PyCFunction) CSysMonitor_get_stats, METH_NOARGS,
            PyDoc_STR("Get statistics (returns None)") },

    /* Event handlers - exposed for registration */
    { "sysmon_py_start", (PyCFunction) CSysMonitor_py_start, METH_VARARGS,
            PyDoc_STR("PY_START event handler") },

    { "sysmon_line_lines", (PyCFunction) CSysMonitor_line_lines, METH_VARARGS,
            PyDoc_STR("LINE event handler for line coverage") },

    { "sysmon_line_arcs", (PyCFunction) CSysMonitor_line_arcs, METH_VARARGS,
            PyDoc_STR("LINE event handler for arc coverage") },

    { "sysmon_py_return", (PyCFunction) CSysMonitor_py_return, METH_VARARGS,
            PyDoc_STR("PY_RETURN event handler") },

    { "sysmon_branch_either", (PyCFunction) CSysMonitor_branch_either, METH_VARARGS,
            PyDoc_STR("BRANCH event handler") },

    { NULL }
};

PyTypeObject
CSysMonitorType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "coverage.CSysMonitor",    /*tp_name*/
    sizeof(CSysMonitor),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)CSysMonitor_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "CSysMonitor objects",     /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    CSysMonitor_methods,       /* tp_methods */
    CSysMonitor_members,       /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)CSysMonitor_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};
