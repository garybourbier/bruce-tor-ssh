/*
 * minitor.h — public API shim for Bruce-TorSSH
 *
 * Real Minitor API (Triple-Layer-Development fork):
 *   int  d_minitor_INIT()
 *   int  d_setup_onion_service(local_port, exit_port, dir)
 *      → writes <dir>/hostname file with the .onion address
 *   (no cleanup function — daemon runs until reboot)
 *
 * Populate submodules then set -DMINITOR_READY=1:
 *   lib/minitor/src/minitor/   ← Triple-Layer-Development/minitor
 *   lib/minitor/src/wolfssl/   ← jpbland1/wolfssl (patched ed25519)
 */

#ifndef MINITOR_SHIM_H
#define MINITOR_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MINITOR_READY
  #include "minitor/include/minitor.h"
  #include "minitor/include/minitor_service.h"
#else
  int d_minitor_INIT(void);
  int d_setup_onion_service(unsigned short local_port, unsigned short exit_port, const char *onion_service_directory);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MINITOR_SHIM_H */
