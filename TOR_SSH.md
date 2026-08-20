# Tor SSH — SSH over a Tor v3 onion service

`Others → Tor SSH` turns the T-Embed into an **SSH server reachable through its own
Tor v3 `.onion` address**, with no port forwarding, no public IP and no exit node.
The whole Tor hidden service runs on the ESP32-S3 itself via an embedded
[Minitor](https://github.com/Triple-Layer-Development/minitor) client — the board
builds its own circuits, publishes its descriptor to the HSDirs and accepts
introductions, then serves a libssh session over the rendezvous circuit.

> **Fork feature.** This module lives in `garybourbier/bruce-tor-ssh` and is not
> (yet) part of upstream Bruce. See [Status & limitations](#status--limitations).

## What you get

- A stable `.onion` address, persisted on the SD card and reused every boot.
- A persistent ECDSA host key (also on SD) — no
  `REMOTE HOST IDENTIFICATION HAS CHANGED` warning after a reboot.
- Login as user `bruce`, any password.

## Usage

1. Insert a FAT-formatted microSD (used to persist the Tor keys and host key).
2. On the board: `Others → Tor SSH`, then pick your WiFi in the selector.
3. Wait for the Tor consensus to download (first run ~5–10 min; the screen stays
   still during the download — this is expected, the TFT and SD share the SPI
   bus). Subsequent boots are faster thanks to the SD cache.
4. The screen shows the `.onion` address once the descriptor is published.
5. From a machine with Tor running:

   ```sh
   torsocks ssh -p 22 bruce@<your-address>.onion
   ```

   User `bruce`, any password. `ESC` on the board stops the service.

## Files on the SD

| Path | Purpose |
|------|---------|
| `/sd/tor_ssh/hs/` | Tor v3 onion service keys (generated once by Minitor) |
| `/sd/tor_ssh/ssh_host_ecdsa_key` | Persistent SSH host key (OpenSSH base64) |

Holding the card == holding the device: both keys are stored unencrypted.

## Architecture

- **Minitor** (`lib/minitor/`) — Tor v3 client/onion-service implementation.
  wolfSSL (jpbland1 fork) for TLS, mbedcrypto backend for libssh.
- **LibSSH-ESP32** — SSH server, host key handled in-memory (the fopen-based
  `ssh_pki_*_file` path and PEM export are unusable on the ESP-IDF FAT VFS, so
  keys are read/written with POSIX I/O and passed to libssh as base64).
- **`src/modules/others/tor_ssh.cpp`** — glue: WiFi, SD, UI, key persistence,
  Minitor + SSH lifecycle.

## Status & limitations

**Works:** onion address and host key persist across reboots; the service
publishes to all 16 HSDirs and is reachable end-to-end (full SSH handshake) when
freshly started.

**Open problem — liveness on mobile NAT.** On an aggressive NAT (mobile / CGNAT
hotspot) the intro-point OR connections are dropped silently by the router: the
board's `write()` of the keepalive padding still succeeds locally (kernel buffers
it for ~15 min of TCP retransmits), so passive keepalive never detects the death
and the service becomes unreachable a few minutes after publishing. This
reproduces identically across two different mobile networks, so it is a Minitor
circuit-maintenance issue, not a single hotspot.

A proper fix needs **active dead-connection detection** (padding + read-timeout:
mark an intro dead if no traffic is received within N seconds) plus **backoff on
circuit rebuilds** (a naive periodic rebuild spirals into a circuit storm). Until
then, the workaround is to **relaunch the module** (which rebuilds intros and
republishes) and connect within 2–3 minutes.

Contributions on the liveness front are welcome.
