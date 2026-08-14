/*
 * minitor_stub.c
 *
 * Stub implementations that compile but abort at runtime with a clear message.
 * Replace by populating the real Minitor submodule and setting -DMINITOR_READY=1.
 */

#ifndef MINITOR_READY

#include <stdio.h>
#include "minitor.h"

int d_minitor_INIT(void) {
    printf("[minitor] STUB: populate lib/minitor/src/minitor/ submodule and set -DMINITOR_READY=1\n");
    return -1;
}

int d_setup_onion_service(int local_port, int onion_port, const char *data_dir) {
    (void)local_port; (void)onion_port; (void)data_dir;
    printf("[minitor] STUB: d_setup_onion_service not implemented\n");
    return -1;
}

const char *d_minitor_get_onion_address(const char *data_dir) {
    (void)data_dir;
    return "stub_not_ready.onion";
}

void d_minitor_cleanup(void) {
    printf("[minitor] STUB: cleanup\n");
}

#endif /* !MINITOR_READY */
