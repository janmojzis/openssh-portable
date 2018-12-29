/*
20181225
Jan Mojzis
Public domain.
*/

#include "crypto_api.h"
/* #include "randombytes.h"
#include "crypto_hash_sha512.h"
#include "crypto_scalarmult_curve25519.h" */
#include "crypto_kem_sntrup4591761.h"
#include "crypto_kem_sntrup4591761x25519.h"

#define sntrup4591761_BYTES crypto_kem_sntrup4591761_BYTES
#define x25519_BYTES crypto_scalarmult_curve25519_BYTES

static const unsigned char basepoint[crypto_scalarmult_curve25519_BYTES] = {9};

int crypto_kem_sntrup4591761x25519_tinynacl_enc(unsigned char *c,
                                                unsigned char *k,
                                                const unsigned char *pk) {

    int r = 0;
    unsigned char onetimesk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char kk[sntrup4591761_BYTES + x25519_BYTES];

    /* sntrup4591761 */
    r |= crypto_kem_sntrup4591761_enc(c, kk, pk);
    pk += crypto_kem_sntrup4591761_PUBLICKEYBYTES;
    c += crypto_kem_sntrup4591761_CIPHERTEXTBYTES;

    /* x25519 */
    randombytes(onetimesk, sizeof onetimesk);
    r |= crypto_scalarmult_curve25519(/*onetimepk*/ c, onetimesk, basepoint);
    r |= crypto_scalarmult_curve25519(kk + sntrup4591761_BYTES, onetimesk, pk);

    /* hash together sntrup459176 KEM-key and x25519 shared secret */
    if (r != 0)
        randombytes(kk, sizeof kk);
    crypto_hash_sha512(k, kk, sizeof kk);
    return r;
}

int crypto_kem_sntrup4591761x25519_tinynacl_dec(unsigned char *k,
                                                const unsigned char *c,
                                                const unsigned char *sk) {

    int r = 0;
    unsigned char kk[sntrup4591761_BYTES + x25519_BYTES];

    /* sntrup4591761 */
    r |= crypto_kem_sntrup4591761_dec(kk, c, sk);
    sk += crypto_kem_sntrup4591761_SECRETKEYBYTES;
    c += crypto_kem_sntrup4591761_CIPHERTEXTBYTES;

    /* x25519 */
    r |= crypto_scalarmult_curve25519(kk + sntrup4591761_BYTES, sk, c);

    /* hash together sntrup459176 KEM-key and x25519 shared secret */
    if (r != 0)
        randombytes(kk, sizeof kk);
    crypto_hash_sha512(k, kk, sizeof kk);
    return r;
}

int crypto_kem_sntrup4591761x25519_tinynacl_keypair(unsigned char *pk,
                                                    unsigned char *sk) {

    int r = 0;

    /* sntrup4591761 */
    r |= crypto_kem_sntrup4591761_keypair(pk, sk);
    pk += crypto_kem_sntrup4591761_PUBLICKEYBYTES;
    sk += crypto_kem_sntrup4591761_SECRETKEYBYTES;

    /* x25519 */
    randombytes(sk, crypto_scalarmult_curve25519_SCALARBYTES);
    r |= crypto_scalarmult_curve25519(pk, sk, basepoint);

    return r;
}
