/* ed25519_sign_msg_custom.c
 * Custom Ed25519 sign-from-fd for Minitor Tor v3 hidden services.
 *
 * Called by minitor/src/onion_service.c with a key in expanded form
 * (key->expanded=1) and possibly unclamped scalar (key->no_clamp=1).
 *
 * This function is missing from jpbland1/wolfssl; we implement it here.
 */
#include <unistd.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/ge_operations.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

/* Feed the file content from position 0 into sha, then restore position */
static int _sha512_feed_fd(wc_Sha512 *sha, int fd)
{
    unsigned char buf[256];
    ssize_t n;
    int ret = 0;

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ret = wc_Sha512Update(sha, buf, (word32)n);
        if (ret != 0)
            return ret;
    }
    return (n < 0) ? -1 : 0;
}

/*
 * Sign all content written to fd (from byte 0 to current position).
 * Key may be pre-expanded (key->expanded) and unclamped (key->no_clamp).
 * Returns 0 on success, negative on error.
 * Sets *outLen = ED25519_SIG_SIZE (64) on success.
 */
int ed25519_sign_msg_custom(int fd, byte *out, word32 *outLen,
                            ed25519_key *key)
{
    int ret;
    ge_p3 R;
    byte  az[ED25519_PRV_KEY_SIZE];
    byte  nonce[WC_SHA512_DIGEST_SIZE];
    byte  hram[WC_SHA512_DIGEST_SIZE];
    wc_Sha512 sha;

    if (out == NULL || outLen == NULL || key == NULL || fd < 0)
        return BAD_FUNC_ARG;
    if (*outLen < ED25519_SIG_SIZE) {
        *outLen = ED25519_SIG_SIZE;
        return BUFFER_E;
    }
    *outLen = ED25519_SIG_SIZE;

    /* Get 64-byte expanded key: (scalar || nonce_key) */
    if (key->expanded) {
        XMEMCPY(az, key->k, ED25519_PRV_KEY_SIZE);
    } else {
        ret = wc_Sha512Hash(key->k, ED25519_KEY_SIZE, az);
        if (ret != 0)
            return ret;
    }

    /* Clamp scalar unless Tor blinded key */
    if (!key->no_clamp) {
        az[0]  &= 248;
        az[31] &= 63;
        az[31] |= 64;
    }

    /* nonce = SHA512(az[32:64] || file_content) */
    ret = wc_InitSha512(&sha);
    if (ret != 0) return ret;
    ret = wc_Sha512Update(&sha, az + ED25519_KEY_SIZE, ED25519_KEY_SIZE);
    if (ret == 0) ret = _sha512_feed_fd(&sha, fd);
    if (ret == 0) ret = wc_Sha512Final(&sha, nonce);
    wc_Sha512Free(&sha);
    if (ret != 0) return ret;

    /* R = sc_reduce(nonce) * B  →  out[0:32] */
    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(out, &R);

    /* hram = SHA512(R || pubkey || file_content) */
    ret = wc_InitSha512(&sha);
    if (ret != 0) return ret;
    ret  = wc_Sha512Update(&sha, out, ED25519_SIG_SIZE / 2);
    if (ret == 0)
        ret = wc_Sha512Update(&sha, key->p, ED25519_PUB_KEY_SIZE);
    if (ret == 0)
        ret = _sha512_feed_fd(&sha, fd);
    if (ret == 0)
        ret = wc_Sha512Final(&sha, hram);
    wc_Sha512Free(&sha);
    if (ret != 0) return ret;

    /* S = (nonce + sc_reduce(hram) * az[0:32]) mod l  →  out[32:64] */
    sc_reduce(hram);
    sc_muladd(out + ED25519_SIG_SIZE / 2, hram, az, nonce);

    return 0;
}

/*
 * Sign a byte buffer with an expanded/unclamped key (Tor blinded key).
 * Same logic as ed25519_sign_msg_custom but takes a buffer instead of fd.
 */
int ed25519_sign_buf_custom(const byte *msg, word32 msg_len,
                            byte *out, word32 *outLen,
                            ed25519_key *key)
{
    int ret;
    ge_p3 R;
    byte  az[ED25519_PRV_KEY_SIZE];
    byte  nonce[WC_SHA512_DIGEST_SIZE];
    byte  hram[WC_SHA512_DIGEST_SIZE];
    wc_Sha512 sha;

    if (msg == NULL || out == NULL || outLen == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (*outLen < ED25519_SIG_SIZE) {
        *outLen = ED25519_SIG_SIZE;
        return BUFFER_E;
    }
    *outLen = ED25519_SIG_SIZE;

    if (key->expanded) {
        XMEMCPY(az, key->k, ED25519_PRV_KEY_SIZE);
    } else {
        ret = wc_Sha512Hash(key->k, ED25519_KEY_SIZE, az);
        if (ret != 0)
            return ret;
    }

    if (!key->no_clamp) {
        az[0]  &= 248;
        az[31] &= 63;
        az[31] |= 64;
    }

    /* nonce = SHA512(az[32:64] || msg) */
    ret = wc_InitSha512(&sha);
    if (ret != 0) return ret;
    ret = wc_Sha512Update(&sha, az + ED25519_KEY_SIZE, ED25519_KEY_SIZE);
    if (ret == 0) ret = wc_Sha512Update(&sha, msg, msg_len);
    if (ret == 0) ret = wc_Sha512Final(&sha, nonce);
    wc_Sha512Free(&sha);
    if (ret != 0) return ret;

    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(out, &R);

    /* hram = SHA512(R || pubkey || msg) */
    ret = wc_InitSha512(&sha);
    if (ret != 0) return ret;
    ret  = wc_Sha512Update(&sha, out, ED25519_SIG_SIZE / 2);
    if (ret == 0)
        ret = wc_Sha512Update(&sha, key->p, ED25519_PUB_KEY_SIZE);
    if (ret == 0)
        ret = wc_Sha512Update(&sha, msg, msg_len);
    if (ret == 0)
        ret = wc_Sha512Final(&sha, hram);
    wc_Sha512Free(&sha);
    if (ret != 0) return ret;

    sc_reduce(hram);
    sc_muladd(out + ED25519_SIG_SIZE / 2, hram, az, nonce);

    return 0;
}
