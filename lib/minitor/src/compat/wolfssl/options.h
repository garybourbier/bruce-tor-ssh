/*
 * wolfssl/options.h — compat stub for PlatformIO/Arduino builds.
 *
 * wolfSSL normally generates this from ./configure. When WOLFSSL_USER_SETTINGS
 * is defined (as in our build flags), settings.h ignores options.h content and
 * uses wolfssl_user_settings.h instead. This stub just satisfies the #include.
 */
#ifndef WOLFSSL_OPTIONS_H
#define WOLFSSL_OPTIONS_H

/* All real settings live in wolfssl_user_settings.h, included via
 * -DWOLFSSL_USER_SETTINGS which makes wolfssl/wolfcrypt/settings.h
 * pull that file in automatically. Nothing needed here. */

#endif /* WOLFSSL_OPTIONS_H */
