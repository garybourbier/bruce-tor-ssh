/*
 * wolfssl_user_settings.h
 * Minimal wolfSSL config for Minitor on ESP32-S3 (Arduino/PlatformIO)
 * Included via -DWOLFSSL_USER_SETTINGS when MINITOR_READY=1
 */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* TLS 1.3 only */
#define WOLFSSL_TLS13
#define NO_OLD_TLS

/* Curves needed by Tor */
#define HAVE_CURVE25519
#define HAVE_ED25519
#define CURVED25519_SMALL
#define WOLFSSL_ED25519_PERSISTENT_SHA

/* Ciphers */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define HAVE_AES_ECB

/* Hash */
#define HAVE_SHA3
#define WOLFSSL_SHA3
#define HAVE_BLAKE2

/* HKDF / HMAC */
#define HAVE_HKDF
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX

/* Disable unused */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_CERTS
#define NO_SESSION_CACHE
#define WOLFSSL_NO_SOCK      /* we manage sockets ourselves */

/* ESP32 specifics */
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESP32
#define USE_FAST_MATH
#define FP_MAX_BITS 512
#define WOLFSSL_SMALL_STACK

/* POSIX I/O (ESP-IDF VFS) */
#define NO_FILESYSTEM        /* Minitor handles all FS ops itself */
#define WOLFSSL_NO_SOCK

#endif /* WOLFSSL_USER_SETTINGS_H */
