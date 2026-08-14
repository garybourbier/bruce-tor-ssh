/*
 * minitor.h — public API shim for Bruce-TorSSH
 *
 * The actual implementation comes from the Minitor submodule cloned into
 * lib/minitor/src/minitor/ (Triple-Layer-Development fork).
 *
 * To populate:
 *   cd lib/minitor/src
 *   git clone --depth=1 https://github.com/Triple-Layer-Development/minitor minitor
 *   git clone --depth=1 https://github.com/Triple-Layer-Development/minitor-wolfssl wolfssl
 *
 * Then set MINITOR_READY=1 in your build flags.
 */

#ifndef MINITOR_SHIM_H
#define MINITOR_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MINITOR_READY
  /* Real implementation — include Minitor's own header */
  #include "minitor/minitor.h"
#else
  /*
   * Stub declarations used during development / CI before the submodule is
   * populated.  The linker will fail at link time (not compile time) if these
   * stubs are referenced in a final build, giving a clear error message.
   */

  /**
   * Fetch the Tor network consensus and start the Minitor daemon.
   * Blocks for ~300 seconds on first run; fast if consensus is cached on SD.
   * @return 0 on success, negative on error
   */
  int d_minitor_INIT(void);

  /**
   * Register and start a v3 onion hidden service.
   * @param local_port  Port on 127.0.0.1 the service forwards to
   * @param onion_port  Port exposed on the .onion address
   * @param data_dir    Filesystem path for HS keys + descriptor cache
   * @return 0 on success, negative on error
   */
  int d_setup_onion_service(int local_port, int onion_port, const char *data_dir);

  /**
   * Read back the generated .onion hostname (e.g. "abcdef...onion").
   * Returns a pointer to a static buffer valid until next call or cleanup.
   * @param data_dir  Same path passed to d_setup_onion_service
   */
  const char *d_minitor_get_onion_address(const char *data_dir);

  /**
   * Tear down all circuits and free Minitor resources.
   */
  void d_minitor_cleanup(void);

#endif /* MINITOR_READY */

#ifdef __cplusplus
}
#endif

#endif /* MINITOR_SHIM_H */
