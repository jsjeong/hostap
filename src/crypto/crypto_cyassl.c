/*
 * Wrapper functions for OpenSSL libcrypto
 * Copyright (c) 2004-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <cyassl/openssl/opensslv.h>
#include <cyassl/openssl/err.h>
#include <cyassl/openssl/des.h>
//#include <cyassl/openssl/aes.h>
#include <cyassl/openssl/bn.h>
#include <cyassl/openssl/evp.h>
#include <cyassl/openssl/dh.h>
#include <cyassl/openssl/hmac.h>
#include <cyassl/openssl/rand.h>
#ifdef CONFIG_ECC
#include <cyassl/openssl/ec.h>
#endif /* CONFIG_ECC */

#include "common.h"
#include "wpabuf.h"
#include "dh_group5.h"
#include "sha1.h"
#include "sha256.h"
#include "crypto.h"
#include "bignum.h"

/* #if OPENSSL_VERSION_NUMBER < 0x00907000 */
/* #define DES_key_schedule des_key_schedule */
/* #define DES_cblock des_cblock */
/* #define DES_set_key(key, schedule) des_set_key((key), *(schedule)) */
/* #define DES_ecb_encrypt(input, output, ks, enc) \ */
/* 	des_ecb_encrypt((input), (output), *(ks), (enc)) */
/* #endif /\* openssl < 0.9.7 *\/ */

static BIGNUM * get_group5_prime(void)
{
#if OPENSSL_VERSION_NUMBER < 0x00908000
	static const unsigned char RFC3526_PRIME_1536[] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
		0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
		0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
		0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
		0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
		0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
		0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
		0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
		0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
		0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
		0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
		0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
		0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
		0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
		0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
		0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	};
        return BN_bin2bn(RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536), NULL);
#else /* openssl < 0.9.8 */
	return get_rfc3526_prime_1536(NULL);
#endif /* openssl < 0.9.8 */
}

#if OPENSSL_VERSION_NUMBER < 0x00908000
#ifndef OPENSSL_NO_SHA256
#ifndef OPENSSL_FIPS
#define NO_SHA256_WRAPPER
#endif
#endif

#endif /* openssl < 0.9.8 */

#ifdef OPENSSL_NO_SHA256
#define NO_SHA256_WRAPPER
#endif

static int openssl_digest_vector(const EVP_MD *type, size_t num_elem,
				 const u8 *addr[], const size_t *len, u8 *mac)
{
	EVP_MD_CTX ctx;
	size_t i;
	unsigned int mac_len;

	EVP_MD_CTX_init(&ctx);
	if (!EVP_DigestInit(&ctx, type)) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestInit_ex failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	for (i = 0; i < num_elem; i++) {
		if (!EVP_DigestUpdate(&ctx, addr[i], len[i])) {
			wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestUpdate "
				   "failed: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
	}
	if (!EVP_DigestFinal(&ctx, mac, &mac_len)) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DigestFinal failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}

#if 0
int md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_md4(), num_elem, addr, len, mac);
}
#endif

void des_encrypt(const u8 *clear, const u8 *key, u8 *cypher)
{
	u8 pkey[8], next, tmp;
	int i;
	DES_key_schedule ks;

	/* Add parity bits to the key */
	next = 0;
	for (i = 0; i < 7; i++) {
		tmp = key[i];
		pkey[i] = (tmp >> i) | next | 1;
		next = tmp << (7 - i);
	}
	pkey[i] = next | 1;

	DES_set_key_unchecked(&pkey, &ks);
	DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
			DES_ENCRYPT);
}


int rc4_skip(const u8 *key, size_t keylen, size_t skip,
	     u8 *data, size_t data_len)
{
#ifdef OPENSSL_NO_RC4
	return -1;
#else /* OPENSSL_NO_RC4 */
	EVP_CIPHER_CTX ctx;
	int res = -1;
	unsigned char skip_buf[16];

	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_CipherInit(&ctx, EVP_rc4(), NULL, NULL, 1) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx, keylen) ||
	!EVP_CipherInit(&ctx, NULL, (u8 *) key, NULL, 1))
		goto out;

	while (skip >= sizeof(skip_buf)) {
		size_t len = skip;
		if (len > sizeof(skip_buf))
			len = sizeof(skip_buf);
		if (!EVP_Cipher(&ctx, skip_buf, skip_buf, len))
			goto out;
		skip -= len;
	}

	if (EVP_Cipher(&ctx, data, data, data_len))
		res = 0;

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	return res;
#endif /* OPENSSL_NO_RC4 */
}


int md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_md5(), num_elem, addr, len, mac);
}


int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	return openssl_digest_vector(EVP_sha1(), num_elem, addr, len, mac);
}


#ifndef NO_SHA256_WRAPPER
int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len,
		  u8 *mac)
{
	return openssl_digest_vector(EVP_sha256(), num_elem, addr, len, mac);
}
#endif /* NO_SHA256_WRAPPER */


static const EVP_CIPHER * aes_get_evp_cipher(size_t keylen)
{
	switch (keylen) {
	case 16:
		return EVP_aes_128_cbc();
	case 24:
		return EVP_aes_192_cbc();
	case 32:
		return EVP_aes_256_cbc();
	}

	return NULL;
}


void * aes_encrypt_init(const u8 *key, size_t len)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;

	type = aes_get_evp_cipher(len);
	if (type == NULL)
		return NULL;

	ctx = os_malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	EVP_CIPHER_CTX_init(ctx);
	if (EVP_CipherInit(ctx, type, (u8 *) key, NULL, 1) != 1) {
		os_free(ctx);
		return NULL;
	}
	return ctx;
}


void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
	EVP_CIPHER_CTX *c = ctx;
	if (EVP_Cipher(c, crypt, (u8 *) plain, 16) != 1) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_EncryptUpdate failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
	}
}


void aes_encrypt_deinit(void *ctx)
{
	EVP_CIPHER_CTX *c = ctx;
	/* u8 buf[16]; */
	/* int len = sizeof(buf); */
	/* if (EVP_EncryptFinal_ex(c, buf, &len) != 1) { */
	/* 	wpa_printf(MSG_ERROR, "OpenSSL: EVP_EncryptFinal_ex failed: " */
	/* 		   "%s", ERR_error_string(ERR_get_error(), NULL)); */
	/* } */
	/* if (len != 0) { */
	/* 	wpa_printf(MSG_ERROR, "OpenSSL: Unexpected padding length %d " */
	/* 		   "in AES encrypt", len); */
	/* } */
	EVP_CIPHER_CTX_cleanup(c);
	os_free(c);
}


void * aes_decrypt_init(const u8 *key, size_t len)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;

	type = aes_get_evp_cipher(len);
	if (type == NULL)
		return NULL;

	ctx = os_malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	EVP_CIPHER_CTX_init(ctx);
	if (EVP_CipherInit(ctx, type, (u8 *) key, NULL, 0) != 1) {
		os_free(ctx);
		return NULL;
	}
	return ctx;
}


void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain)
{
	EVP_CIPHER_CTX *c = ctx;
	if (EVP_Cipher(c, plain, (u8 *) crypt, 16) != 1) {
		wpa_printf(MSG_ERROR, "OpenSSL: EVP_DecryptUpdate failed: %s",
			   ERR_error_string(ERR_get_error(), NULL));
	}
}


void aes_decrypt_deinit(void *ctx)
{
	EVP_CIPHER_CTX *c = ctx;
	/* u8 buf[16]; */
	/* int len = sizeof(buf); */
	/* if (EVP_DecryptFinal_ex(c, buf, &len) != 1) { */
	/* 	wpa_printf(MSG_ERROR, "OpenSSL: EVP_DecryptFinal_ex failed: " */
	/* 		   "%s", ERR_error_string(ERR_get_error(), NULL)); */
	/* } */
	/* if (len != 0) { */
	/* 	wpa_printf(MSG_ERROR, "OpenSSL: Unexpected padding length %d " */
	/* 		   "in AES decrypt", len); */
	/* } */
	EVP_CIPHER_CTX_cleanup(c);
	os_free(ctx);
}

struct crypto_cipher {
	EVP_CIPHER_CTX enc;
	EVP_CIPHER_CTX dec;
};


struct crypto_cipher * crypto_cipher_init(enum crypto_cipher_alg alg,
					  const u8 *iv, const u8 *key,
					  size_t key_len)
{
	struct crypto_cipher *ctx;
	const EVP_CIPHER *cipher;

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	switch (alg) {
#ifndef NO_RC4
	case CRYPTO_CIPHER_ALG_RC4:
		cipher = EVP_rc4();
		break;
#endif /* NO_RC4 */
#ifndef NO_AES
	case CRYPTO_CIPHER_ALG_AES:
		switch (key_len) {
		case 16:
			cipher = EVP_aes_128_cbc();
			break;
		case 24:
			cipher = EVP_aes_192_cbc();
			break;
		case 32:
			cipher = EVP_aes_256_cbc();
			break;
		default:
			os_free(ctx);
			return NULL;
		}
		break;
#endif /* NO_AES */
#ifndef NO_DES
	case CRYPTO_CIPHER_ALG_3DES:
		cipher = EVP_des_ede3_cbc();
		break;
	case CRYPTO_CIPHER_ALG_DES:
		cipher = EVP_des_cbc();
		break;
#endif /* NO_DES */
/* #ifndef NO_RC2 */
/* 	case CRYPTO_CIPHER_ALG_RC2: */
/* 		cipher = EVP_rc2_ecb(); */
/* 		break; */
/* #endif /\* NO_RC2 *\/ */
	default:
		os_free(ctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->enc);
	if (!EVP_CipherInit(&ctx->enc, cipher, NULL, NULL, 1) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->enc, key_len) ||
	    !EVP_CipherInit(&ctx->enc, NULL, (u8 *) key, (u8 *) iv, 1)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		os_free(ctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->dec);
	if (!EVP_CipherInit(&ctx->dec, cipher, NULL, NULL, 0) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->dec, key_len) ||
	    !EVP_CipherInit(&ctx->dec, NULL, (u8 *) key, (u8 *) iv, 0)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		EVP_CIPHER_CTX_cleanup(&ctx->dec);
		os_free(ctx);
		return NULL;
	}

	return ctx;
}


int crypto_cipher_encrypt(struct crypto_cipher *ctx, const u8 *plain,
			  u8 *crypt, size_t len)
{
  if (!EVP_Cipher(&ctx->enc, crypt, (u8 *) plain, len))
		return -1;
	return 0;
}


int crypto_cipher_decrypt(struct crypto_cipher *ctx, const u8 *crypt,
			  u8 *plain, size_t len)
{
  if (!EVP_Cipher(&ctx->dec, plain, (u8 *) crypt, len))
		return -1;
	return 0;
}


void crypto_cipher_deinit(struct crypto_cipher *ctx)
{
	EVP_CIPHER_CTX_cleanup(&ctx->enc);
	EVP_CIPHER_CTX_cleanup(&ctx->dec);
	os_free(ctx);
}


void * dh5_init(struct wpabuf **priv, struct wpabuf **publ)
{
	DH *dh;
	struct wpabuf *pubkey = NULL, *privkey = NULL;
	size_t publen, privlen;

	*priv = NULL;
	*publ = NULL;

	dh = DH_new();
	if (dh == NULL)
		return NULL;

	dh->g = BN_new();
	if (dh->g == NULL || BN_set_word(dh->g, 2) != 1)
		goto err;

	dh->p = get_group5_prime();
	if (dh->p == NULL)
		goto err;

	if (DH_generate_key(dh) != 1)
		goto err;

	publen = BN_num_bytes(dh->pub_key);
	pubkey = wpabuf_alloc(publen);
	if (pubkey == NULL)
		goto err;
	privlen = BN_num_bytes(dh->priv_key);
	privkey = wpabuf_alloc(privlen);
	if (privkey == NULL)
		goto err;

	BN_bn2bin(dh->pub_key, wpabuf_put(pubkey, publen));
	BN_bn2bin(dh->priv_key, wpabuf_put(privkey, privlen));

	*priv = privkey;
	*publ = pubkey;
	return dh;

err:
	wpabuf_free(pubkey);
	wpabuf_free(privkey);
	DH_free(dh);
	return NULL;
}


void * dh5_init_fixed(const struct wpabuf *priv, const struct wpabuf *publ)
{
	DH *dh;

	dh = DH_new();
	if (dh == NULL)
		return NULL;

	dh->g = BN_new();
	if (dh->g == NULL || BN_set_word(dh->g, 2) != 1)
		goto err;

	dh->p = get_group5_prime();
	if (dh->p == NULL)
		goto err;

	dh->priv_key = BN_bin2bn(wpabuf_head(priv), wpabuf_len(priv), NULL);
	if (dh->priv_key == NULL)
		goto err;

	dh->pub_key = BN_bin2bn(wpabuf_head(publ), wpabuf_len(publ), NULL);
	if (dh->pub_key == NULL)
		goto err;

	if (DH_generate_key(dh) != 1)
		goto err;

	return dh;

err:
	DH_free(dh);
	return NULL;
}


struct wpabuf * dh5_derive_shared(void *ctx, const struct wpabuf *peer_public,
				  const struct wpabuf *own_private)
{
	BIGNUM *pub_key;
	struct wpabuf *res = NULL;
	size_t rlen;
	DH *dh = ctx;
	int keylen;

	if (ctx == NULL)
		return NULL;

	pub_key = BN_bin2bn(wpabuf_head(peer_public), wpabuf_len(peer_public),
			    NULL);
	if (pub_key == NULL)
		return NULL;

	rlen = DH_size(dh);
	res = wpabuf_alloc(rlen);
	if (res == NULL)
		goto err;

	keylen = DH_compute_key(wpabuf_mhead(res), pub_key, dh);
	if (keylen < 0)
		goto err;
	wpabuf_put(res, keylen);
	BN_free(pub_key);

	return res;

err:
	BN_free(pub_key);
	wpabuf_free(res);
	return NULL;
}


void dh5_free(void *ctx)
{
	DH *dh;
	if (ctx == NULL)
		return;
	dh = ctx;
	DH_free(dh);
}


struct crypto_hash {
	HMAC_CTX ctx;
};


struct crypto_hash * crypto_hash_init(enum crypto_hash_alg alg, const u8 *key,
				      size_t key_len)
{
	struct crypto_hash *ctx;
	const EVP_MD *md;

	switch (alg) {
#ifndef NO_MD5
	case CRYPTO_HASH_ALG_HMAC_MD5:
		md = EVP_md5();
		break;
#endif /* NO_MD5 */
#ifndef NO_SHA
	case CRYPTO_HASH_ALG_HMAC_SHA1:
		md = EVP_sha1();
		break;
#endif /* NO_SHA */
#ifndef NO_SHA256
#ifdef CONFIG_SHA256
	case CRYPTO_HASH_ALG_HMAC_SHA256:
		md = EVP_sha256();
		break;
#endif /* CONFIG_SHA256 */
#endif /* NO_SHA256 */
	default:
		return NULL;
	}

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	HMAC_Init(&ctx->ctx, key, key_len, md);

	return ctx;
}


void crypto_hash_update(struct crypto_hash *ctx, const u8 *data, size_t len)
{
	if (ctx == NULL)
		return;
	HMAC_Update(&ctx->ctx, data, len);
}


int crypto_hash_finish(struct crypto_hash *ctx, u8 *mac, size_t *len)
{
	unsigned int mdlen;
	int res;

	if (ctx == NULL)
		return -2;

	if (mac == NULL || len == NULL) {
		os_free(ctx);
		return 0;
	}

	mdlen = *len;
	HMAC_Final(&ctx->ctx, mac, &mdlen);
	res = 1;
	HMAC_cleanup(&ctx->ctx);
	os_free(ctx);

	if (res == 1) {
		*len = mdlen;
		return 0;
	}

	return -1;
}


/* int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len, */
/* 		int iterations, u8 *buf, size_t buflen) */
/* { */
/* #if OPENSSL_VERSION_NUMBER < 0x00908000 */
/* 	if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, os_strlen(passphrase), */
/* 				   (unsigned char *) ssid, */
/* 				   ssid_len, 4096, buflen, buf) != 1) */
/* 		return -1; */
/* #else /\* openssl < 0.9.8 *\/ */
/* 	if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, os_strlen(passphrase), ssid, */
/* 				   ssid_len, 4096, buflen, buf) != 1) */
/* 		return -1; */
/* #endif /\* openssl < 0.9.8 *\/ */
/* 	return 0; */
/* } */


int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
	HMAC_CTX ctx;
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_Init(&ctx, key, key_len, EVP_sha1());

	for (i = 0; i < num_elem; i++)
		HMAC_Update(&ctx, addr[i], len[i]);

	mdlen = 20;
	HMAC_Final(&ctx, mac, &mdlen);
	res = 1;
	HMAC_cleanup(&ctx);

	return res == 1 ? 0 : -1;
}


int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	       u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}


#ifdef CONFIG_SHA256

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac)
{
	HMAC_CTX ctx;
	size_t i;
	unsigned int mdlen;
	int res;

	HMAC_CTX_init(&ctx);
#if OPENSSL_VERSION_NUMBER < 0x00909000
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), NULL);
#else /* openssl < 0.9.9 */
	if (HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), NULL) != 1)
		return -1;
#endif /* openssl < 0.9.9 */

	for (i = 0; i < num_elem; i++)
		HMAC_Update(&ctx, addr[i], len[i]);

	mdlen = 32;
#if OPENSSL_VERSION_NUMBER < 0x00909000
	HMAC_Final(&ctx, mac, &mdlen);
	res = 1;
#else /* openssl < 0.9.9 */
	res = HMAC_Final(&ctx, mac, &mdlen);
#endif /* openssl < 0.9.9 */
	HMAC_CTX_cleanup(&ctx);

	return res == 1 ? 0 : -1;
}


int hmac_sha256(const u8 *key, size_t key_len, const u8 *data,
		size_t data_len, u8 *mac)
{
	return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}

#endif /* CONFIG_SHA256 */


int crypto_get_random(void *buf, size_t len)
{
	if (RAND_bytes(buf, len) != 1)
		return -1;
	return 0;
}


#ifdef CONFIG_OPENSSL_CMAC
int omac1_aes_128_vector(const u8 *key, size_t num_elem,
			 const u8 *addr[], const size_t *len, u8 *mac)
{
	CMAC_CTX *ctx;
	int ret = -1;
	size_t outlen, i;

	ctx = CMAC_CTX_new();
	if (ctx == NULL)
		return -1;

	if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL))
		goto fail;
	for (i = 0; i < num_elem; i++) {
		if (!CMAC_Update(ctx, addr[i], len[i]))
			goto fail;
	}
	if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16)
		goto fail;

	ret = 0;
fail:
	CMAC_CTX_free(ctx);
	return ret;
}


int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
#endif /* CONFIG_OPENSSL_CMAC */
