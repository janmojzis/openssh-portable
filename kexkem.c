/*
 key exchange using KEM (key encapsulation mechanism) 
*/

#include "includes.h"

#include <sys/types.h>

#include <signal.h>

#include "openbsd-compat/openssl-compat.h"

#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"

int
kex_kem_hash(
    int hash_alg,
    const struct sshbuf *client_version,
    const struct sshbuf *server_version,
    const u_char *ckexinit, size_t ckexinitlen,
    const u_char *skexinit, size_t skexinitlen,
    const u_char *serverhostkeyblob, size_t sbloblen,
    const u_char *client_kex_pub, size_t client_kex_publen,
    const u_char *server_kex_ciphertext, size_t server_kex_ciphertextlen,
    const u_char *kex_key, size_t kex_keylen,
    u_char *hash, size_t *hashlen)
{
	struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(hash_alg))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
    if ((r = sshbuf_put_stringb(b, client_version)) < 0 ||
        (r = sshbuf_put_stringb(b, server_version)) < 0 ||
        /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
        (r = sshbuf_put_u32(b, ckexinitlen+1)) < 0 ||
        (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) < 0 ||
        (r = sshbuf_put(b, ckexinit, ckexinitlen)) < 0 ||
        (r = sshbuf_put_u32(b, skexinitlen+1)) < 0 ||
        (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) < 0 ||
        (r = sshbuf_put(b, skexinit, skexinitlen)) < 0 ||
        (r = sshbuf_put_string(b, serverhostkeyblob, sbloblen)) < 0 ||
        (r = sshbuf_put_string(b, client_kex_pub, client_kex_publen)) < 0 ||
        (r = sshbuf_put_string(b, server_kex_ciphertext, server_kex_ciphertextlen)) < 0 ||
        (r = sshbuf_put(b, kex_key, kex_keylen)) != 0) {
        sshbuf_free(b);
        return r;
    }
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	return 0;
}
