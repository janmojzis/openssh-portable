/*
 key exchange using KEM (key encapsulation mechanism) 
*/
#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#include "crypto_kem_sntrup4591761x25519.h"

static int
input_kex_kem_reply(int type, u_int32_t seq, struct ssh *ssh);

int
kexkem_client(struct ssh *ssh)
{
    struct kex *kex = ssh->kex;
    int r;

    switch (kex->kex_type) {
    case KEX_KEM_SNTRUP4591761X25519_SHA512:
        kex->kem_client_pubkeylen = crypto_kem_sntrup4591761x25519_PUBLICKEYBYTES;
        kex->kem_client_keylen = crypto_kem_sntrup4591761x25519_SECRETKEYBYTES;
        if (sizeof(kex->kem_client_pubkey) < kex->kem_client_pubkeylen) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        if (sizeof(kex->kem_client_key) < kex->kem_client_keylen) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        crypto_kem_sntrup4591761x25519_keypair(kex->kem_client_pubkey, kex->kem_client_key);
        break;
    default:
        return SSH_ERR_INVALID_ARGUMENT;
    }

#ifdef DEBUG_KEXECDH
    dump_digest("client private key:", kex->kem_client_key,
        kex->kem_client_keylen);
#endif
    if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_KEM_INIT)) != 0 ||
        (r = sshpkt_put_string(ssh, kex->kem_client_pubkey,
        kex->kem_client_pubkeylen)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        return r;

    debug("expecting SSH2_MSG_KEX_KEM_REPLY");
    ssh_dispatch_set(ssh, SSH2_MSG_KEX_KEM_REPLY, &input_kex_kem_reply);
    return 0;
}

static int
input_kex_kem_reply(int type, u_int32_t seq, struct ssh *ssh)
{
    struct kex *kex = ssh->kex;
    struct sshkey *server_host_key = NULL;
    struct sshbuf *kex_key = NULL;
    u_char *server_ciphertext = NULL;
    u_char *server_host_key_blob = NULL, *signature = NULL;
    u_char hash[SSH_DIGEST_MAX_LENGTH];
    size_t slen, ciphertextlen, sbloblen, hashlen;
    int r;

    if (kex->verify_host_key == NULL) {
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }

    /* hostkey */
    if ((r = sshpkt_get_string(ssh, &server_host_key_blob,
        &sbloblen)) != 0 ||
        (r = sshkey_from_blob(server_host_key_blob, sbloblen,
        &server_host_key)) != 0)
        goto out;
    if (server_host_key->type != kex->hostkey_type ||
        (kex->hostkey_type == KEY_ECDSA &&
        server_host_key->ecdsa_nid != kex->hostkey_nid)) {
        r = SSH_ERR_KEY_TYPE_MISMATCH;
        goto out;
    }
    if (kex->verify_host_key(server_host_key, ssh) == -1) {
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    if ((r = sshpkt_get_string(ssh, &server_ciphertext, &ciphertextlen)) != 0 ||
        (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
        (r = sshpkt_get_end(ssh)) != 0)
        goto out;

#ifdef DEBUG_KEXECDH
    dump_digest("server ciphertext:", server_ciphertext, ciphertextlen);
#endif

    if ((kex_key = sshbuf_new()) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    switch (kex->kex_type) {
    case KEX_KEM_SNTRUP4591761X25519_SHA512:
        if (ciphertextlen != crypto_kem_sntrup4591761x25519_CIPHERTEXTBYTES) {
            r = SSH_ERR_INVALID_ARGUMENT;
            goto out;
        }
        if (crypto_kem_sntrup4591761x25519_BYTES > sizeof(hash)) {
            r = SSH_ERR_INVALID_ARGUMENT;
            goto out;
        }
        if (crypto_kem_sntrup4591761x25519_dec(hash, server_ciphertext, kex->kem_client_key) != 0) {
            arc4random_buf(hash, crypto_kem_sntrup4591761x25519_BYTES);
        }
        sshbuf_reset(kex_key);
        r = sshbuf_put_string(kex_key, hash, crypto_kem_sntrup4591761x25519_BYTES);
        if (r != 0) goto out;
        break;
    default:
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }


    /* calc and verify H */
    hashlen = sizeof(hash);
    if ((r = kex_kem_hash(
        kex->hash_alg,
        kex->client_version,
        kex->server_version,
        sshbuf_ptr(kex->my), sshbuf_len(kex->my),
        sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
        server_host_key_blob, sbloblen,
        kex->kem_client_pubkey, kex->kem_client_pubkeylen,
        server_ciphertext, ciphertextlen,
        sshbuf_ptr(kex_key), sshbuf_len(kex_key),
        hash, &hashlen)) < 0)
        goto out;

    if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
        kex->hostkey_alg, ssh->compat)) != 0)
        goto out;

    /* save session id */
    if (kex->session_id == NULL) {
        kex->session_id_len = hashlen;
        kex->session_id = malloc(kex->session_id_len);
        if (kex->session_id == NULL) {
            r = SSH_ERR_ALLOC_FAIL;
            goto out;
        }
        memcpy(kex->session_id, hash, kex->session_id_len);
    }

    if ((r = kex_derive_keys(ssh, hash, hashlen, kex_key)) == 0)
        r = kex_send_newkeys(ssh);
out:
    explicit_bzero(hash, sizeof(hash));
    explicit_bzero(kex->kem_client_key, sizeof(kex->kem_client_key));
    free(server_host_key_blob);
    free(server_ciphertext);
    free(signature);
    sshkey_free(server_host_key);
    sshbuf_free(kex_key);
    return r;
}
