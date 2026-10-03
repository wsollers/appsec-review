#include "config.h"
#include "app.h"
#include "minijson.h"
#include <stdio.h>
#include <zlib.h>

int main(void) {
    printf("%s %s %d\n", APP_GREETING, zlibVersion(), minijson_answer());
    return APP_OK;
}
