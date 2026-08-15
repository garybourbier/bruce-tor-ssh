/*
 * Stub implementations — compile but fail at runtime.
 * Replaced by real Minitor when -DMINITOR_READY=1 and submodule populated.
 */
#ifndef MINITOR_READY

#include <stdio.h>
#include "minitor.h"

int d_minitor_INIT(void) {
    printf("[minitor] STUB: set -DMINITOR_READY=1 after running setup_minitor.sh\n");
    return -1;
}

int d_setup_onion_service(unsigned short local_port, unsigned short exit_port, const char *dir) {
    (void)local_port; (void)exit_port; (void)dir;
    printf("[minitor] STUB: d_setup_onion_service not implemented\n");
    return -1;
}

#endif /* !MINITOR_READY */
