/*
 * user_settings.h — wolfSSL configuration for Minitor on ESP32-S3 Arduino.
 * Included by wolfssl/wolfcrypt/settings.h when WOLFSSL_USER_SETTINGS is set.
 *
 * Key points:
 * - RSA kept ON: Minitor uses RSA to verify relay TLS identity certificates
 * - WOLFSSL_OPENSSL_EXTRA needed: Minitor calls wolfSSL_get_client/server_random
 *   to extract TLS session keys for Tor's KDF
 * - Software-only crypto: avoids esp32/rom/aes.h (ESP32 vs ESP32-S3 path issue)
 */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* TLS 1.2 only — Tor relay link protocol uses TLS 1.2.
 * TLS 1.3 is deliberately NOT enabled: it requires HAVE_TLS_EXTENSIONS,
 * HAVE_FFDHE_*, WC_RSA_PSS which cascade into many more defines. */
#define WOLFSSL_ALLOW_TLSV10
#define WOLFSSL_ALLOW_TLSV11

/* OpenSSL compat layer — required by Minitor for:
 *   wolfSSL_get_client_random / wolfSSL_get_server_random
 *   wolfSSL_EVP_PKEY_free, wolfSSL_X509_* */
#define OPENSSL_EXTRA
#define HAVE_SECRET_CALLBACK

/* Curves needed by Tor v3 hidden services */
#define HAVE_ECC        /* needed by OPENSSL_EXTRA group/curve name lookup in ssl.c */
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_PERSISTENT_SHA
/* SHA512 is required by ED25519 internals */
#define HAVE_SHA512
#define WOLFSSL_SHA512

/* Certificate generation — Minitor generates self-signed TLS certs for relay
 * connections (Cert.subject field used in circuit.c) */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_ALT_NAMES

/* Ciphers */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define HAVE_AES_ECB

/* Hash */
#define HAVE_SHA3
#define WOLFSSL_SHA3

/* Key derivation */
#define HAVE_HKDF

/* RSA — required for Tor relay certificate verification */
#define RSA_MIN_SIZE 1024
/* Key generation — required by Minitor to generate ephemeral RSA TLS certs */
#define WOLFSSL_KEY_GEN
/* AES direct (single-block) — required by Minitor (guard is WOLFSSL_AES_DIRECT) */
#define WOLFSSL_AES_DIRECT

/* Math — use SP (Single Precision) math for speed + smaller stack */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SMALL_STACK

/* Disable unused features to save flash */
#define NO_MD4
#define NO_RC4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED

/* Software-only crypto on ESP32-S3.
 * Avoids esp32/rom/aes.h which doesn't exist on S3 variant. */
#define NO_ESP32_CRYPT
#define NO_WOLFSSL_ESP32_CRYPT_HASH
#define NO_WOLFSSL_ESP32_CRYPT_AES
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI

/* Minitor manages all file I/O via POSIX open/read/write on /sd/ */
#define NO_FILESYSTEM

/* Random source: ESP32 hardware TRNG via esp_random() */
#define CUSTOM_RAND_GENERATE    esp_random
#define CUSTOM_RAND_TYPE        uint32_t
#include <esp_system.h>

#endif /* WOLFSSL_USER_SETTINGS_H */
