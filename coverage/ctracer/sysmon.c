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

/* Cached constant from sys.monitoring */
static PyObject *cached_disable = NULL;

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

int
CSysMonitor_cache_constants(void)
{
    int ret = RET_ERROR;
    PyObject *sys_module = NULL;
    PyObject *monitoring = NULL;

    /* Cache sys.monitoring.DISABLE to avoid importing sys in callbacks */
    sys_module = PyImport_ImportModule("sys");
    if (sys_module == NULL) {
        goto error;
    }

    monitoring = PyObject_GetAttr(sys_module, str_monitoring);
    if (monitoring == NULL) {
        goto error;
    }

    cached_disable = PyObject_GetAttr(monitoring, str_DISABLE);
    if (cached_disable == NULL) {
        goto error;
    }

    ret = RET_OK;

error:
    Py_XDECREF(sys_module);
    Py_XDECREF(monitoring);

    return ret;
}

/* Helper to get sys.monitoring module */
static PyObject *
get_monitoring_module(void)
{
    PyObject *sys_module = NULL;
    PyObject *monitoring = NULL;

    sys_module = PyImport_ImportModule("sys");
    if (sys_module == NULL) {
        goto error;
    }

    monitoring = PyObject_GetAttr(sys_module, str_monitoring);
    if (monitoring == NULL) {
        goto error;
    }

    Py_XDECREF(sys_module);
    return monitoring;

error:
    Py_XDECREF(sys_module);
    Py_XDECREF(monitoring);
    return NULL;
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
    CodeInfo *info = NULL;
    PyObject *capsule = NULL;

    info = PyMem_Malloc(sizeof(CodeInfo));
    if (info == NULL) {
        PyErr_NoMemory();
        goto error;
    }

    info->tracing = tracing;
    info->file_data = file_data;  /* Borrowed reference */
    info->byte_to_line = byte_to_line;
    Py_XINCREF(byte_to_line);
    info->branch_trails = PyDict_New();
    info->always_jumps = PyDict_New();

    if (info->branch_trails == NULL || info->always_jumps == NULL) {
        goto error;
    }

    capsule = PyCapsule_New(info, "CodeInfo", CodeInfo_dealloc);
    if (capsule == NULL) {
        goto error;
    }

    return capsule;

error:
    if (info != NULL) {
        Py_XDECREF(info->branch_trails);
        Py_XDECREF(info->always_jumps);
        Py_XDECREF(info->byte_to_line);
        PyMem_Free(info);
    }
    return NULL;
}

/* Helper: bytes_to_lines - create dict mapping byte offset to line number */
static PyObject *
bytes_to_lines(PyCodeObject *code)
{
    PyObject *b2l = NULL;
    PyObject *co_lines_iter = NULL;
    PyObject *item = NULL;
    PyObject *offset_key = NULL;

    b2l = PyDict_New();
    if (b2l == NULL) {
        goto error;
    }

    /* Call code.co_lines() to get the line number table */
    co_lines_iter = PyObject_CallMethodNoArgs((PyObject *)code, str_co_lines);
    if (co_lines_iter == NULL) {
        goto error;
    }

    while ((item = PyIter_Next(co_lines_iter)) != NULL) {
        /* Each item is (bstart, bend, lineno) */
        PyObject *bstart_obj, *bend_obj, *lineno_obj;
        if (!PyArg_ParseTuple(item, "OOO", &bstart_obj, &bend_obj, &lineno_obj)) {
            goto error;
        }

        /* Skip if lineno is None */
        if (lineno_obj != Py_None) {
            long bstart = PyLong_AsLong(bstart_obj);
            long bend = PyLong_AsLong(bend_obj);

            if (bstart == -1 || bend == -1) {
                if (PyErr_Occurred()) {
                    goto error;
                }
            }

            /* Map each offset in range [bstart, bend) with step 2 */
            for (long boffset = bstart; boffset < bend; boffset += 2) {
                offset_key = PyLong_FromLong(boffset);
                if (offset_key == NULL) {
                    goto error;
                }

                if (PyDict_SetItem(b2l, offset_key, lineno_obj) < 0) {
                    goto error;
                }
                Py_XDECREF(offset_key);
                offset_key = NULL;
            }
        }

        Py_XDECREF(item);
        item = NULL;
    }

    if (PyErr_Occurred()) {
        goto error;
    }

    Py_XDECREF(co_lines_iter);
    return b2l;

error:
    Py_XDECREF(offset_key);
    Py_XDECREF(item);
    Py_XDECREF(co_lines_iter);
    Py_XDECREF(b2l);
    return NULL;
}

/* Helper to call Python functions for branch_trails and always_jumps */
static int
populate_branch_info(CodeInfo *info, PyCodeObject *code, PyObject *multiline_map)
{
    int ret = RET_ERROR;
    PyObject *bytecode_module = NULL;
    PyObject *branch_trails_func = NULL;
    PyObject *args = NULL;
    PyObject *kwargs = NULL;
    PyObject *trails = NULL;
    PyObject *always_jumps_func = NULL;
    PyObject *jumps = NULL;

    /* Import coverage.bytecode module */
    bytecode_module = PyImport_ImportModule("coverage.bytecode");
    if (bytecode_module == NULL) {
        goto error;
    }

    /* Call branch_trails(code, multiline_map=multiline_map) */
    branch_trails_func = PyObject_GetAttrString(bytecode_module, "branch_trails");
    if (branch_trails_func == NULL) {
        goto error;
    }

    args = PyTuple_Pack(1, code);
    kwargs = PyDict_New();
    if (args == NULL || kwargs == NULL) {
        goto error;
    }

    PyDict_SetItemString(kwargs, "multiline_map", multiline_map);

    trails = PyObject_Call(branch_trails_func, args, kwargs);
    if (trails == NULL) {
        goto error;
    }

    Py_DECREF(info->branch_trails);
    info->branch_trails = trails;
    trails = NULL;

    /* Call always_jumps(code) */
    always_jumps_func = PyObject_GetAttrString(bytecode_module, "always_jumps");
    if (always_jumps_func == NULL) {
        goto error;
    }

    jumps = PyObject_CallFunctionObjArgs(always_jumps_func, code, NULL);
    if (jumps == NULL) {
        goto error;
    }

    Py_DECREF(info->always_jumps);
    info->always_jumps = jumps;
    jumps = NULL;

    ret = RET_OK;

error:
    Py_XDECREF(bytecode_module);
    Py_XDECREF(branch_trails_func);
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    Py_XDECREF(trails);
    Py_XDECREF(always_jumps_func);
    Py_XDECREF(jumps);

    return ret;
}

/* Helper to get multiline_map from PythonParser */
static PyObject *
get_multiline_map(const char *filename)
{
    PyObject *parser_module = NULL;
    PyObject *parser_class = NULL;
    PyObject *kwargs = NULL;
    PyObject *filename_str = NULL;
    PyObject *empty_tuple = NULL;
    PyObject *parser = NULL;
    PyObject *result = NULL;
    PyObject *multiline_map = NULL;

    parser_module = PyImport_ImportModule("coverage.parser");
    if (parser_module == NULL) {
        goto error;
    }

    parser_class = PyObject_GetAttrString(parser_module, "PythonParser");
    if (parser_class == NULL) {
        goto error;
    }

    /* Create parser with filename */
    kwargs = PyDict_New();
    if (kwargs == NULL) {
        goto error;
    }

    filename_str = PyUnicode_FromString(filename);
    if (filename_str == NULL) {
        goto error;
    }

    PyDict_SetItemString(kwargs, "filename", filename_str);

    empty_tuple = PyTuple_New(0);
    if (empty_tuple == NULL) {
        goto error;
    }

    parser = PyObject_Call(parser_class, empty_tuple, kwargs);
    if (parser == NULL) {
        goto check_expected_exception;
    }

    /* Call parse_source() */
    result = PyObject_CallMethod(parser, "parse_source", NULL);
    if (result == NULL) {
        goto check_expected_exception;
    }

    /* Get multiline_map attribute */
    multiline_map = PyObject_GetAttrString(parser, "multiline_map");
    if (multiline_map == NULL) {
        goto error;
    }

    Py_XDECREF(parser_module);
    Py_XDECREF(parser_class);
    Py_XDECREF(kwargs);
    Py_XDECREF(filename_str);
    Py_XDECREF(empty_tuple);
    Py_XDECREF(parser);
    Py_XDECREF(result);
    return multiline_map;

check_expected_exception:
    /* Handle NotPython or NoSource exceptions by returning empty dict */
    if (PyErr_Occurred()) {
        PyObject *exc_type = NULL;
        PyObject *exc_value = NULL;
        PyObject *exc_tb = NULL;
        PyObject *exceptions_module = NULL;
        PyObject *NotPython = NULL;
        PyObject *NoSource = NULL;
        int is_expected = 0;

        PyErr_Fetch(&exc_type, &exc_value, &exc_tb);

        exceptions_module = PyImport_ImportModule("coverage.exceptions");
        if (exceptions_module != NULL) {
            NotPython = PyObject_GetAttrString(exceptions_module, "NotPython");
            NoSource = PyObject_GetAttrString(exceptions_module, "NoSource");

            if (NotPython != NULL && PyErr_GivenExceptionMatches(exc_type, NotPython)) {
                is_expected = 1;
            }
            if (NoSource != NULL && PyErr_GivenExceptionMatches(exc_type, NoSource)) {
                is_expected = 1;
            }

            if (is_expected) {
                Py_XDECREF(exc_type);
                Py_XDECREF(exc_value);
                Py_XDECREF(exc_tb);
                Py_XDECREF(NotPython);
                Py_XDECREF(NoSource);
                Py_XDECREF(exceptions_module);
                Py_XDECREF(parser_module);
                Py_XDECREF(parser_class);
                Py_XDECREF(kwargs);
                Py_XDECREF(filename_str);
                Py_XDECREF(empty_tuple);
                Py_XDECREF(parser);
                Py_XDECREF(result);
                return PyDict_New();
            }
        }

        PyErr_Restore(exc_type, exc_value, exc_tb);
        Py_XDECREF(NotPython);
        Py_XDECREF(NoSource);
        Py_XDECREF(exceptions_module);
    }

error:
    Py_XDECREF(parser_module);
    Py_XDECREF(parser_class);
    Py_XDECREF(kwargs);
    Py_XDECREF(filename_str);
    Py_XDECREF(empty_tuple);
    Py_XDECREF(parser);
    Py_XDECREF(result);
    Py_XDECREF(multiline_map);
    return NULL;
}

/*
 * CSysMonitor initialization and deallocation
 */

static int
CSysMonitor_init(CSysMonitor *self, PyObject *args, PyObject *kwds)
{
    int ret = RET_ERROR;
    int tool_id = 1;  /* Default tool_id */
    PyObject *threading = NULL;

    static char *kwlist[] = {"tool_id", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &tool_id)) {
        goto error;
    }

    self->myid = tool_id;
    self->sysmon_on = FALSE;
    atomic_store(&self->activity, FALSE);
    self->tracing_arcs = FALSE;

    /* Create code_infos dict */
    self->code_infos = PyDict_New();
    if (self->code_infos == NULL) {
        goto error;
    }

    /* Create code_objects list */
    self->code_objects = PyList_New(0);
    if (self->code_objects == NULL) {
        goto error;
    }

    /* Create threading lock */
    threading = PyImport_ImportModule("threading");
    if (threading == NULL) {
        goto error;
    }

    self->lock = PyObject_CallMethod(threading, "Lock", NULL);
    if (self->lock == NULL) {
        goto error;
    }

    ret = RET_OK;

error:
    Py_XDECREF(threading);

    return ret;
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
    PyCodeObject *code = NULL;
    int instruction_offset;
    PyObject *code_id = NULL;
    PyObject *capsule = NULL;
    CodeInfo *code_info = NULL;
    BOOL tracing_code = FALSE;
    PyObject *file_data = NULL;
    PyObject *filename = NULL;
    PyObject *disp = NULL;
    PyObject *frame = NULL;
    PyObject *trace_attr = NULL;
    PyObject *byte_to_line = NULL;
    PyObject *source_filename = NULL;
    PyObject *lock_result = NULL;
    PyObject *unlock_result = NULL;
    PyObject *new_file_data = NULL;
    PyObject *monitoring = NULL;
    PyObject *events_obj = NULL;
    PyObject *py_return = NULL;
    PyObject *py_resume = NULL;
    PyObject *line = NULL;
    PyObject *branch_right = NULL;
    PyObject *branch_left = NULL;
    PyObject *events_long = NULL;
    PyObject *myid_long = NULL;
    PyObject *set_result = NULL;
    PyObject *exit_result = NULL;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &instruction_offset)) {
        goto error;
    }

    atomic_store(&self->activity, TRUE);

    /* Skip __annotate__ functions */
    if (strcmp(PyUnicode_AsUTF8(code->co_name), "__annotate__") == 0) {
        Py_INCREF(cached_disable);
        return cached_disable;
    }

    /* Check if we already have info for this code object */
    code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        goto error;
    }

    capsule = PyDict_GetItem(self->code_infos, code_id);

    if (capsule != NULL) {
        code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL) {
            tracing_code = code_info->tracing;
            file_data = code_info->file_data;
        }
    }

    if (code_info == NULL) {
        /* Need to determine if we should trace this file */
        filename = code->co_filename;
        disp = PyDict_GetItem(self->should_trace_cache, filename);

        if (disp == NULL) {
            /* Call should_trace(filename, frame) */
            PyFrameObject *current_frame = PyEval_GetFrame();
            if (current_frame != NULL) {
                Py_INCREF(current_frame);
                frame = (PyObject *)current_frame;
            }

            disp = PyObject_CallFunctionObjArgs(self->should_trace, filename, frame, NULL);
            if (disp == NULL) {
                goto error;
            }

            if (PyDict_SetItem(self->should_trace_cache, filename, disp) < 0) {
                goto error;
            }
            Py_XDECREF(disp);
            disp = NULL;
            disp = PyDict_GetItem(self->should_trace_cache, filename);
        }

        /* Check if we should trace */
        trace_attr = PyObject_GetAttrString(disp, "trace");
        if (trace_attr == NULL) {
            goto error;
        }

        tracing_code = (trace_attr == Py_True);
        Py_XDECREF(trace_attr);
        trace_attr = NULL;

        if (tracing_code) {
            source_filename = PyObject_GetAttrString(disp, "source_filename");
            if (source_filename == NULL) {
                goto error;
            }

            /* Lock data and get/create file_data set */
            lock_result = PyObject_CallNoArgs(self->lock_data);
            if (lock_result == NULL) {
                goto error;
            }
            Py_XDECREF(lock_result);
            lock_result = NULL;

            file_data = PyDict_GetItem(self->data, source_filename);
            if (file_data == NULL) {
                new_file_data = PySet_New(NULL);
                if (new_file_data == NULL) {
                    PyObject_CallNoArgs(self->unlock_data);
                    goto error;
                }

                if (PyDict_SetItem(self->data, source_filename, new_file_data) < 0) {
                    PyObject_CallNoArgs(self->unlock_data);
                    goto error;
                }
                Py_XDECREF(new_file_data);
                new_file_data = NULL;
                file_data = PyDict_GetItem(self->data, source_filename);
            }

            unlock_result = PyObject_CallNoArgs(self->unlock_data);
            if (unlock_result == NULL) {
                goto error;
            }
            Py_XDECREF(unlock_result);
            unlock_result = NULL;
            Py_XDECREF(source_filename);
            source_filename = NULL;

            /* Create byte_to_line mapping */
            byte_to_line = bytes_to_lines(code);
            if (byte_to_line == NULL) {
                goto error;
            }
        }

        /* Create CodeInfo */
        capsule = CodeInfo_new(tracing_code, file_data, byte_to_line);
        Py_XDECREF(byte_to_line);
        byte_to_line = NULL;

        if (capsule == NULL) {
            goto error;
        }

        if (PyDict_SetItem(self->code_infos, code_id, capsule) < 0) {
            goto error;
        }
        Py_XDECREF(capsule);
        capsule = NULL;

        capsule = PyDict_GetItem(self->code_infos, code_id);

        /* Keep code object alive */
        if (PyList_Append(self->code_objects, (PyObject *)code) < 0) {
            goto error;
        }

        code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");

        /* Enable local events for this code if tracing */
        if (tracing_code) {
            lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
            if (lock_result == NULL) {
                goto error;
            }
            Py_XDECREF(lock_result);
            lock_result = NULL;

            if (self->sysmon_on) {
                monitoring = get_monitoring_module();
                if (monitoring == NULL) {
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    goto error;
                }

                events_obj = PyObject_GetAttr(monitoring, str_events);
                if (events_obj == NULL) {
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    goto error;
                }

                /* Build local_events mask */
                py_return = PyObject_GetAttr(events_obj, str_PY_RETURN);
                py_resume = PyObject_GetAttr(events_obj, str_PY_RESUME);
                line = PyObject_GetAttr(events_obj, str_LINE);

                if (py_return == NULL || py_resume == NULL || line == NULL) {
                    PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
                    goto error;
                }

                long local_events = PyLong_AsLong(py_return) | PyLong_AsLong(py_resume) | PyLong_AsLong(line);
                Py_XDECREF(py_return);
                py_return = NULL;
                Py_XDECREF(py_resume);
                py_resume = NULL;
                Py_XDECREF(line);
                line = NULL;

                /* Add branch events if tracing arcs */
                if (self->tracing_arcs) {
                    branch_right = PyObject_GetAttr(events_obj, str_BRANCH_RIGHT);
                    branch_left = PyObject_GetAttr(events_obj, str_BRANCH_LEFT);

                    if (branch_right != NULL && branch_left != NULL) {
                        local_events |= PyLong_AsLong(branch_right) | PyLong_AsLong(branch_left);
                    }

                    Py_XDECREF(branch_right);
                    branch_right = NULL;
                    Py_XDECREF(branch_left);
                    branch_left = NULL;
                }

                Py_XDECREF(events_obj);
                events_obj = NULL;

                /* Call sys.monitoring.set_local_events(myid, code, local_events) */
                events_long = PyLong_FromLong(local_events);
                myid_long = PyLong_FromLong(self->myid);

                if (events_long != NULL && myid_long != NULL) {
                    set_result = PyObject_CallMethod(monitoring, "set_local_events", "OOO",
                                       myid_long, code, events_long);
                    Py_XDECREF(set_result);
                    set_result = NULL;
                }

                Py_XDECREF(events_long);
                events_long = NULL;
                Py_XDECREF(myid_long);
                myid_long = NULL;
                Py_XDECREF(monitoring);
                monitoring = NULL;
            }

            exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
            Py_XDECREF(exit_result);
            exit_result = NULL;
        }
    }

    Py_XDECREF(code_id);
    Py_XDECREF(frame);

    /* Return DISABLE */
    Py_INCREF(cached_disable);
    return cached_disable;

error:
    Py_XDECREF(code_id);
    Py_XDECREF(frame);
    Py_XDECREF(disp);
    Py_XDECREF(trace_attr);
    Py_XDECREF(byte_to_line);
    Py_XDECREF(source_filename);
    Py_XDECREF(lock_result);
    Py_XDECREF(unlock_result);
    Py_XDECREF(new_file_data);
    Py_XDECREF(capsule);
    Py_XDECREF(monitoring);
    Py_XDECREF(events_obj);
    Py_XDECREF(py_return);
    Py_XDECREF(py_resume);
    Py_XDECREF(line);
    Py_XDECREF(branch_right);
    Py_XDECREF(branch_left);
    Py_XDECREF(events_long);
    Py_XDECREF(myid_long);
    Py_XDECREF(set_result);
    Py_XDECREF(exit_result);
    return NULL;
}

/* LINE event handler for line coverage */
static PyObject *
CSysMonitor_line_lines(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code = NULL;
    int line_number;
    PyObject *code_id = NULL;
    PyObject *capsule = NULL;
    PyObject *line_obj = NULL;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &line_number)) {
        goto error;
    }

    code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        goto error;
    }

    capsule = PyDict_GetItem(self->code_infos, code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->file_data != NULL) {
            line_obj = PyLong_FromLong(line_number);
            if (line_obj == NULL) {
                goto error;
            }
            PySet_Add(code_info->file_data, line_obj);
            Py_XDECREF(line_obj);
            line_obj = NULL;
        }
    }

    Py_XDECREF(code_id);

    Py_INCREF(cached_disable);
    return cached_disable;

error:
    Py_XDECREF(code_id);
    Py_XDECREF(line_obj);
    return NULL;
}

/* LINE event handler for arc coverage */
static PyObject *
CSysMonitor_line_arcs(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code = NULL;
    int line_number;
    PyObject *code_id = NULL;
    PyObject *capsule = NULL;
    PyObject *line_num_obj = NULL;
    PyObject *arc = NULL;

    if (!PyArg_ParseTuple(args, "O!i", &PyCode_Type, &code, &line_number)) {
        goto error;
    }

    code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        goto error;
    }

    capsule = PyDict_GetItem(self->code_infos, code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->file_data != NULL) {
            /* Add (line_number, line_number) arc */
            line_num_obj = PyLong_FromLong(line_number);
            if (line_num_obj == NULL) {
                goto error;
            }
            arc = PyTuple_Pack(2, line_num_obj, line_num_obj);
            if (arc == NULL) {
                goto error;
            }
            PySet_Add(code_info->file_data, arc);
            Py_XDECREF(arc);
            arc = NULL;
            Py_XDECREF(line_num_obj);
            line_num_obj = NULL;
        }
    }

    Py_XDECREF(code_id);

    Py_INCREF(cached_disable);
    return cached_disable;

error:
    Py_XDECREF(code_id);
    Py_XDECREF(line_num_obj);
    Py_XDECREF(arc);
    return NULL;
}

/* PY_RETURN event handler */
static PyObject *
CSysMonitor_py_return(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code = NULL;
    int instruction_offset;
    PyObject *retval = NULL;
    PyObject *code_id = NULL;
    PyObject *capsule = NULL;
    PyObject *offset_key = NULL;
    PyObject *last_line = NULL;
    PyObject *last_line_obj = NULL;
    PyObject *first_line_obj = NULL;
    PyObject *arc = NULL;

    if (!PyArg_ParseTuple(args, "O!iO", &PyCode_Type, &code, &instruction_offset, &retval)) {
        goto error;
    }

    code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        goto error;
    }

    capsule = PyDict_GetItem(self->code_infos, code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL && code_info->byte_to_line != NULL) {
            offset_key = PyLong_FromLong(instruction_offset);
            if (offset_key == NULL) {
                goto error;
            }

            last_line = PyDict_GetItem(code_info->byte_to_line, offset_key);

            if (last_line != NULL) {
                long last_line_num = PyLong_AsLong(last_line);
                long first_line = code->co_firstlineno;

                /* Add (last_line, -first_line) arc */
                last_line_obj = PyLong_FromLong(last_line_num);
                first_line_obj = PyLong_FromLong(-first_line);
                if (last_line_obj == NULL || first_line_obj == NULL) {
                    goto error;
                }

                arc = PyTuple_Pack(2, last_line_obj, first_line_obj);
                if (arc == NULL) {
                    goto error;
                }
                PySet_Add(code_info->file_data, arc);
                Py_XDECREF(arc);
                arc = NULL;
                Py_XDECREF(last_line_obj);
                last_line_obj = NULL;
                Py_XDECREF(first_line_obj);
                first_line_obj = NULL;
            }
            Py_XDECREF(offset_key);
            offset_key = NULL;
        }
    }

    Py_XDECREF(code_id);

    Py_INCREF(cached_disable);
    return cached_disable;

error:
    Py_XDECREF(code_id);
    Py_XDECREF(offset_key);
    Py_XDECREF(last_line_obj);
    Py_XDECREF(first_line_obj);
    Py_XDECREF(arc);
    return NULL;
}

/* BRANCH event handler (both BRANCH_RIGHT and BRANCH_LEFT) */
static PyObject *
CSysMonitor_branch_either(CSysMonitor *self, PyObject *args)
{
    PyCodeObject *code = NULL;
    int instruction_offset;
    int destination_offset;
    PyObject *code_id = NULL;
    PyObject *capsule = NULL;
    PyObject *multiline_map = NULL;
    PyObject *empty_map = NULL;
    PyObject *dest_set = NULL;
    PyObject *dest_obj = NULL;
    PyObject *offset_key = NULL;
    PyObject *intersection = NULL;
    PyObject *fallback_offset_key = NULL;
    PyObject *fallback_dest_key = NULL;
    PyObject *fallback_arc = NULL;

    if (!PyArg_ParseTuple(args, "O!ii", &PyCode_Type, &code, &instruction_offset, &destination_offset)) {
        goto error;
    }

    code_id = PyLong_FromVoidPtr((void *)code);
    if (code_id == NULL) {
        goto error;
    }

    capsule = PyDict_GetItem(self->code_infos, code_id);

    if (capsule != NULL) {
        CodeInfo *code_info = (CodeInfo *)PyCapsule_GetPointer(capsule, "CodeInfo");
        if (code_info != NULL) {
            /* Populate branch_trails if not done yet */
            if (PyDict_Size(code_info->branch_trails) == 0) {
                const char *filename = PyUnicode_AsUTF8(code->co_filename);
                if (filename != NULL) {
                    multiline_map = get_multiline_map(filename);
                    if (multiline_map != NULL) {
                        populate_branch_info(code_info, code, multiline_map);
                        Py_XDECREF(multiline_map);
                        multiline_map = NULL;
                    } else {
                        /* Clear error and continue with empty multiline_map */
                        PyErr_Clear();
                        empty_map = PyDict_New();
                        if (empty_map != NULL) {
                            populate_branch_info(code_info, code, empty_map);
                            Py_XDECREF(empty_map);
                            empty_map = NULL;
                        }
                    }
                }
            }

            BOOL added_arc = FALSE;

            /* Re-map destination through always_jumps */
            dest_set = PySet_New(NULL);
            if (dest_set == NULL) {
                goto error;
            }

            dest_obj = PyLong_FromLong(destination_offset);
            if (dest_obj == NULL) {
                goto error;
            }

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

            Py_XDECREF(dest_obj);
            dest_obj = NULL;

            /* Look up branch_trails[instruction_offset] */
            offset_key = PyLong_FromLong(instruction_offset);
            if (offset_key == NULL) {
                goto error;
            }

            PyObject *dest_info = PyDict_GetItem(code_info->branch_trails, offset_key);
            Py_XDECREF(offset_key);
            offset_key = NULL;

            if (dest_info != NULL && PyDict_Check(dest_info)) {
                /* Iterate over dest_info items */
                PyObject *arc = NULL;
                PyObject *offsets = NULL;
                Py_ssize_t pos = 0;

                while (PyDict_Next(dest_info, &pos, &arc, &offsets)) {
                    if (arc == Py_None) {
                        continue;
                    }

                    /* Check if any offset in offsets intersects with dest_set */
                    if (PySet_Check(offsets)) {
                        intersection = PyNumber_And(dest_set, offsets);
                        if (intersection == NULL) {
                            goto error;
                        }

                        Py_ssize_t size = PySet_Size(intersection);
                        Py_XDECREF(intersection);
                        intersection = NULL;

                        if (size > 0) {
                            PySet_Add(code_info->file_data, arc);
                            added_arc = TRUE;
                            break;
                        }
                    }
                }
            }

            Py_XDECREF(dest_set);
            dest_set = NULL;

            /* If no arc was added, try direct line-to-line mapping */
            if (!added_arc && code_info->byte_to_line != NULL) {
                fallback_offset_key = PyLong_FromLong(instruction_offset);
                fallback_dest_key = PyLong_FromLong(destination_offset);

                if (fallback_offset_key == NULL || fallback_dest_key == NULL) {
                    goto error;
                }

                PyObject *l1 = PyDict_GetItem(code_info->byte_to_line, fallback_offset_key);
                PyObject *l2 = PyDict_GetItem(code_info->byte_to_line, fallback_dest_key);

                if (l1 != NULL && l2 != NULL) {
                    long line1 = PyLong_AsLong(l1);
                    long line2 = PyLong_AsLong(l2);

                    if (line1 != line2) {
                        fallback_arc = PyTuple_Pack(2, l1, l2);
                        if (fallback_arc == NULL) {
                            goto error;
                        }
                        PySet_Add(code_info->file_data, fallback_arc);
                        Py_XDECREF(fallback_arc);
                        fallback_arc = NULL;
                    }
                }

                Py_XDECREF(fallback_offset_key);
                fallback_offset_key = NULL;
                Py_XDECREF(fallback_dest_key);
                fallback_dest_key = NULL;
            }
        }
    }

    Py_XDECREF(code_id);

    Py_INCREF(cached_disable);
    return cached_disable;

error:
    Py_XDECREF(code_id);
    Py_XDECREF(multiline_map);
    Py_XDECREF(empty_map);
    Py_XDECREF(dest_set);
    Py_XDECREF(dest_obj);
    Py_XDECREF(offset_key);
    Py_XDECREF(intersection);
    Py_XDECREF(fallback_offset_key);
    Py_XDECREF(fallback_dest_key);
    Py_XDECREF(fallback_arc);
    return NULL;
}

/*
 * Management methods
 */

static PyObject *
CSysMonitor_start(CSysMonitor *self, PyObject *args_unused)
{
    PyObject *lock_result = NULL;
    PyObject *monitoring = NULL;
    PyObject *result = NULL;
    PyObject *events_obj = NULL;
    PyObject *py_start_event = NULL;
    PyObject *callback = NULL;
    PyObject *line_event = NULL;
    PyObject *py_return_event = NULL;
    PyObject *branch_right = NULL;
    PyObject *branch_left = NULL;
    PyObject *exit_result = NULL;

    lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
    if (lock_result == NULL) {
        goto error;
    }
    Py_XDECREF(lock_result);
    lock_result = NULL;

    monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }

    /* use_tool_id(myid, "coverage.py") */
    result = PyObject_CallMethod(monitoring, "use_tool_id", "is", self->myid, "coverage.py");
    if (result == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }
    Py_XDECREF(result);
    result = NULL;

    /* Get events object */
    events_obj = PyObject_GetAttr(monitoring, str_events);
    if (events_obj == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }

    /* Register callbacks */
    py_start_event = PyObject_GetAttr(events_obj, str_PY_START);
    if (py_start_event == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }

    /* Set initial events to PY_START */
    long py_start_value = PyLong_AsLong(py_start_event);
    result = PyObject_CallMethod(monitoring, "set_events", "ii", self->myid, (int)py_start_value);
    if (result == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }
    Py_XDECREF(result);
    result = NULL;

    /* Register PY_START callback */
    callback = PyObject_GetAttrString((PyObject *)self, "sysmon_py_start");
    if (callback == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }

    result = PyObject_CallMethod(monitoring, "register_callback", "iiO", self->myid, (int)py_start_value, callback);
    Py_XDECREF(py_start_event);
    py_start_event = NULL;
    Py_XDECREF(callback);
    callback = NULL;

    if (result == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }
    Py_XDECREF(result);
    result = NULL;

    /* Determine which LINE callback to use */
    self->tracing_arcs = (self->trace_arcs != NULL && self->trace_arcs != Py_None && PyObject_IsTrue(self->trace_arcs));

    line_event = PyObject_GetAttr(events_obj, str_LINE);
    if (line_event != NULL) {
        const char *line_callback_name = self->tracing_arcs ? "sysmon_line_arcs" : "sysmon_line_lines";
        callback = PyObject_GetAttrString((PyObject *)self, line_callback_name);
        long line_value = PyLong_AsLong(line_event);
        result = PyObject_CallMethod(monitoring, "register_callback", "iiO", self->myid, (int)line_value, callback);
        Py_XDECREF(callback);
        callback = NULL;
        Py_XDECREF(result);
        result = NULL;
        Py_XDECREF(line_event);
        line_event = NULL;
    }

    /* Register PY_RETURN if tracing arcs */
    if (self->tracing_arcs) {
        py_return_event = PyObject_GetAttr(events_obj, str_PY_RETURN);
        if (py_return_event != NULL) {
            callback = PyObject_GetAttrString((PyObject *)self, "sysmon_py_return");
            long return_value = PyLong_AsLong(py_return_event);
            result = PyObject_CallMethod(monitoring, "register_callback", "iiO", self->myid, (int)return_value, callback);
            Py_XDECREF(callback);
            callback = NULL;
            Py_XDECREF(result);
            result = NULL;
            Py_XDECREF(py_return_event);
            py_return_event = NULL;
        }

        /* Register BRANCH events */
        branch_right = PyObject_GetAttr(events_obj, str_BRANCH_RIGHT);
        branch_left = PyObject_GetAttr(events_obj, str_BRANCH_LEFT);

        if (branch_right != NULL && branch_left != NULL) {
            callback = PyObject_GetAttrString((PyObject *)self, "sysmon_branch_either");

            long right_value = PyLong_AsLong(branch_right);
            result = PyObject_CallMethod(monitoring, "register_callback", "iiO", self->myid, (int)right_value, callback);
            Py_XDECREF(result);
            result = NULL;

            long left_value = PyLong_AsLong(branch_left);
            result = PyObject_CallMethod(monitoring, "register_callback", "iiO", self->myid, (int)left_value, callback);
            Py_XDECREF(result);
            result = NULL;

            Py_XDECREF(callback);
            callback = NULL;
        }

        Py_XDECREF(branch_right);
        branch_right = NULL;
        Py_XDECREF(branch_left);
        branch_left = NULL;
    }

    Py_XDECREF(events_obj);
    events_obj = NULL;

    /* Call restart_events() */
    result = PyObject_CallMethod(monitoring, "restart_events", NULL);
    Py_XDECREF(result);
    result = NULL;

    Py_XDECREF(monitoring);
    monitoring = NULL;

    self->sysmon_on = TRUE;

    exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
    Py_XDECREF(exit_result);

    Py_RETURN_NONE;

error:
    Py_XDECREF(lock_result);
    Py_XDECREF(monitoring);
    Py_XDECREF(result);
    Py_XDECREF(events_obj);
    Py_XDECREF(py_start_event);
    Py_XDECREF(callback);
    Py_XDECREF(line_event);
    Py_XDECREF(py_return_event);
    Py_XDECREF(branch_right);
    Py_XDECREF(branch_left);
    return NULL;
}

static PyObject *
CSysMonitor_stop(CSysMonitor *self, PyObject *args_unused)
{
    PyObject *lock_result = NULL;
    PyObject *exit_result = NULL;
    PyObject *monitoring = NULL;
    PyObject *myid_obj = NULL;
    PyObject *result = NULL;

    lock_result = PyObject_CallMethod(self->lock, "__enter__", NULL);
    if (lock_result == NULL) {
        goto error;
    }
    Py_XDECREF(lock_result);
    lock_result = NULL;

    if (!self->sysmon_on) {
        exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        Py_XDECREF(exit_result);
        Py_RETURN_NONE;
    }

    monitoring = get_monitoring_module();
    if (monitoring == NULL) {
        PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
        goto error;
    }

    /* set_events(myid, 0) */
    myid_obj = PyLong_FromLong(self->myid);
    if (myid_obj != NULL) {
        result = PyObject_CallMethod(monitoring, "set_events", "Oi", myid_obj, 0);
        Py_XDECREF(result);
        result = NULL;
        Py_XDECREF(myid_obj);
        myid_obj = NULL;
    }

    self->sysmon_on = FALSE;

    /* free_tool_id(myid) */
    myid_obj = PyLong_FromLong(self->myid);
    if (myid_obj != NULL) {
        result = PyObject_CallMethod(monitoring, "free_tool_id", "O", myid_obj);
        Py_XDECREF(result);
        result = NULL;
        Py_XDECREF(myid_obj);
        myid_obj = NULL;
    }

    Py_XDECREF(monitoring);
    monitoring = NULL;

    exit_result = PyObject_CallMethod(self->lock, "__exit__", "OOO", Py_None, Py_None, Py_None);
    Py_XDECREF(exit_result);

    Py_RETURN_NONE;

error:
    Py_XDECREF(lock_result);
    Py_XDECREF(monitoring);
    Py_XDECREF(myid_obj);
    Py_XDECREF(result);
    return NULL;
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
