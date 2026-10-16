/* Dynamic loading makes the module open-world: no SVF answer may contradict CodeQL here. */
#include <dlfcn.h>

typedef void (*entry_fn)(void);

void load_plugin(const char *path) {
    void *handle = dlopen(path, RTLD_NOW);
    if (handle == 0) return;
    entry_fn entry = (entry_fn)dlsym(handle, "plugin_entry");
    if (entry != 0) entry();
}
