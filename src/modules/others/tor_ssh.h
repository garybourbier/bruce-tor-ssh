#ifndef TOR_SSH_H
#define TOR_SSH_H

#if !defined(LITE_VERSION)

#include <Arduino.h>

/*
 * Tor Hidden Service + SSH Server module for Bruce firmware
 *
 * Exposes an SSH shell on a .onion address without any VPS or external relay.
 * Stack: Minitor (embedded Tor HS) + libssh (SSH server) on ESP32-S3.
 *
 * Dependencies (see platformio.ini / lib/minitor):
 *   - Minitor: https://github.com/Triple-Layer-Development/minitor
 *   - LibSSH-ESP32: already in Bruce lib_deps
 */

// Entry point wired into OthersMenu
void tor_ssh_menu();

#endif // LITE_VERSION
#endif // TOR_SSH_H
