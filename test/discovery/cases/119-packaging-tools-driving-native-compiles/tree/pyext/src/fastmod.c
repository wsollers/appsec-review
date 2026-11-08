#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *twice(PyObject *self, PyObject *arg) {
    long value = PyLong_AsLong(arg);
    if (value == -1 && PyErr_Occurred()) return NULL;
    return PyLong_FromLong(value * 2);
}

static PyMethodDef methods[] = {{"twice", twice, METH_O, "double a value"}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_fastmod", NULL, -1, methods};

PyMODINIT_FUNC PyInit__fastmod(void) { return PyModule_Create(&module); }
