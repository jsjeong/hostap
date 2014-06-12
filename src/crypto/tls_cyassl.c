/*
 * SSL/TLS interface functions for CyaSSL
 * Copyright (c) 2014, Jongsoo Jeong <skywk84@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <cyassl/options.h>
#include <cyassl/ssl.h>
#include <cyassl/openssl/ssl.h>
#include <cyassl/openssl/err.h>
#include <cyassl/openssl/pkcs12.h>
#include <cyassl/openssl/x509v3.h>
#include <cyassl/openssl/evp.h>

#include "common.h"
#include "crypto.h"
#include "tls.h"

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#define OPENSSL_d2i_TYPE const unsigned char **
#else
#define OPENSSL_d2i_TYPE unsigned char **
#endif

#ifdef SSL_F_SSL_SET_SESSION_TICKET_EXT
#ifdef SSL_OP_NO_TICKET
/*
 * Session ticket override patch was merged into OpenSSL 0.9.9 tree on
 * 2008-11-15. This version uses a bit different API compared to the old patch.
 */
#define CONFIG_OPENSSL_TICKET_OVERRIDE
#endif
#endif

#ifdef SSL_set_tlsext_status_type
#ifndef OPENSSL_NO_TLSEXT
#define HAVE_OCSP
#include <openssl/ocsp.h>
#endif /* OPENSSL_NO_TLSEXT */
#endif /* SSL_set_tlsext_status_type */

static int tls_openssl_ref_count = 0;

struct tls_context {
  void (*event_cb)(void *ctx, enum tls_event ev,
		   union tls_event_data *data);
  void *cb_ctx;
  int cert_in_cb;
  char *ocsp_stapling_response;
};

static struct tls_context *tls_global = NULL;


struct tls_connection {
  struct tls_context *context;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
  struct wpabuf *ssl_in, *ssl_out;
  char *subject_match, *altsubject_match, *suffix_match;
  int read_alerts, write_alerts, failed;

  tls_session_ticket_cb session_ticket_cb;
  void *session_ticket_cb_ctx;

  /* SessionTicket received from OpenSSL hello_extension_cb (server) */
  u8 *session_ticket;
  size_t session_ticket_len;

  unsigned int ca_cert_verify:1;
  unsigned int cert_probe:1;
  unsigned int server_cert_only:1;
  unsigned int invalid_hb_used:1;

  u8 srv_cert_hash[32];

  unsigned int flags;

  X509 *peer_cert;
  X509 *peer_issuer;
  X509 *peer_issuer_issuer;
};

#define MAX_CONN 10
struct tls_connection *ssl_conn[MAX_CONN];

static struct tls_context * tls_context_new(const struct tls_config *conf)
{
  struct tls_context *context = os_zalloc(sizeof(*context));
  if (context == NULL)
    return NULL;
  if (conf) {
    context->event_cb = conf->event_cb;
    context->cb_ctx = conf->cb_ctx;
    context->cert_in_cb = conf->cert_in_cb;
  }
  return context;
}

/**
 * @note It shoud be registered by CyaSSL_SetIORecv() to be called by CyaSSL to
 *       receive data.
 */
static int input_data(CYASSL *ssl, char *buf, int sz, void *ctx)
{
  int i, rcvd;
  struct tls_connection *conn = NULL;

  for (i = 0; i < MAX_CONN; i++) {
    if (ssl_conn[i] && ssl_conn[i]->ssl == ssl) {
      conn = ssl_conn[i];
      break;
    }
  }

  if (!conn)
    return CYASSL_CBIO_ERR_CONN_CLOSE;

  wpa_printf(MSG_DEBUG, "%s-i:%d, conn->ssl_in:%p, sz:%u",
	     __func__, i, conn->ssl_in, sz);

  if (!conn->ssl_in)
    return CYASSL_CBIO_ERR_WANT_READ;

  rcvd = wpabuf_len(conn->ssl_in);
  if (rcvd <= sz) {
    memcpy(buf, wpabuf_head(conn->ssl_in), rcvd);
    wpabuf_free(conn->ssl_in);
    conn->ssl_in = NULL;

    wpa_printf(MSG_DEBUG, "%s-rcvd:%u", __func__, rcvd);
    return rcvd;

  } else {
    struct wpabuf *remain = NULL;

    os_memcpy(buf, wpabuf_head(conn->ssl_in), sz);

    if (rcvd > sz)
      remain = wpabuf_alloc(rcvd - sz);

    if (remain) {
      wpabuf_put_data(remain, wpabuf_head_u8(conn->ssl_in) + sz, rcvd - sz);
    }

    wpabuf_free(conn->ssl_in);
    conn->ssl_in = remain;

    if (remain || rcvd == sz) {
      wpa_printf(MSG_DEBUG, "%s-rcvd:%u, remain:%u", __func__, sz, rcvd - sz);
      return sz;
    } else {
      return CYASSL_CBIO_ERR_GENERAL;
    }
  }
}

/**
 * @note It should be registered by CyaSSL_SetIOSend() to be called by CyaSSL to
 *       send data.
 */
static int output_data(CYASSL *ssl, char *buf, int sz, void *ctx)
{
  int i;
  int total_len;
  struct tls_connection *conn = NULL;
  struct wpabuf *out;

  for (i = 0; i < MAX_CONN; i++) {
    if (ssl_conn[i] && ssl_conn[i]->ssl == ssl) {
      conn = ssl_conn[i];
      break;
    }
  }

  wpa_printf(MSG_INFO, "%s-i:%d, conn->ssl_out:%p (%u bytes), sz:%d (%p)",
	     __func__, i, conn->ssl_out,
	     ((conn->ssl_out) ? wpabuf_len(conn->ssl_out) : 0), sz, buf);

  if (!conn)
    return CYASSL_CBIO_ERR_CONN_CLOSE;

  total_len = sz + ((conn->ssl_out) ? wpabuf_len(conn->ssl_out) : 0);
  wpa_printf(MSG_DEBUG, "%s-%u=%d+%u",
	     __func__, total_len, sz,
	     ((conn->ssl_out) ? wpabuf_len(conn->ssl_out) : 0));

  out = wpabuf_alloc(total_len);
  if (!out)
    return CYASSL_CBIO_ERR_GENERAL;

  if (conn->ssl_out) {
    wpabuf_put_data(out, wpabuf_head(conn->ssl_out), wpabuf_len(conn->ssl_out));
    wpabuf_free(conn->ssl_out);
  }

  wpabuf_put_data(out, buf, sz);
  conn->ssl_out = out;

  return sz;
}

void * tls_init(const struct tls_config *conf)
{
  int i;
  SSL_CTX *ssl_ctx;
  struct tls_connection *conn = NULL;

  if (tls_openssl_ref_count == 0) {

    /* Initialize ssl_conn[]. */
    for (i = 0; i < MAX_CONN; i++) {
      ssl_conn[i] = NULL;
    }

    tls_global = tls_context_new(conf);
    if (tls_global == NULL)
      return NULL;

    CyaSSL_Debugging_ON();
  }

  tls_openssl_ref_count++;

  for (i = 0; i < MAX_CONN; i++) {
    if (ssl_conn[i] == NULL) {
      conn = os_malloc(sizeof(struct tls_connection));
      break;
    }
  }

  if (!conn) {
    goto err;
  }

  if (conf->server) {
    ssl_ctx = CyaSSL_CTX_new(CyaTLSv1_2_server_method());
  } else {
    ssl_ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method());
  }

  if (ssl_ctx == NULL) {
    goto err;
  }

  /* Save SSL_CTX. */
  conn->ssl_ctx = ssl_ctx;
  ssl_conn[i] = conn;

  /* Set custom I/O abstraction layer. */
  CyaSSL_SetIORecv(ssl_ctx, input_data);
  CyaSSL_SetIOSend(ssl_ctx, output_data);

  wpa_printf(MSG_DEBUG, "%s-i:%u (%s)",
	     __func__, i, (conf->server) ? "server" : "client");
  return ssl_ctx;

 err:
  tls_openssl_ref_count--;
  if (tls_openssl_ref_count == 0) {
    os_free(tls_global);
    tls_global = NULL;
  }

  if (conn) os_free(conn);
  return NULL;
}


void tls_deinit(void *ssl_ctx)
{
  CyaSSL_CTX_free((SSL_CTX *) ssl_ctx);

  tls_openssl_ref_count--;
  if (tls_openssl_ref_count == 0) {
    os_free(tls_global->ocsp_stapling_response);
    tls_global->ocsp_stapling_response = NULL;
    os_free(tls_global);
    tls_global = NULL;
  }
}



int tls_get_errors(void *ssl_ctx)
{
  int i;
  int count = 0;
  struct tls_connection *conn = NULL;
  int err;

  for (i = 0; i < MAX_CONN; i++) {
    if (ssl_conn[i] && ssl_conn[i]->ssl_ctx == ssl_ctx) {
      conn = ssl_conn[i];
      break;
    }
  }

  if (!conn) {
    wpa_printf(MSG_INFO, "TLS - no conn err");
    return -1;
  }

  while ((err = CyaSSL_get_error(conn->ssl, 0)) < 0) {
    wpa_printf(MSG_INFO, "TLS - SSL error: %d", err);
    count++;
  }

  return count;
}

struct tls_connection * tls_connection_init(void *ssl_ctx)
{
  struct tls_connection *conn = NULL;
  int i;

  for (i = 0; i < MAX_CONN; i++) {
    if (ssl_conn[i] &&
	ssl_conn[i]->ssl_ctx == (SSL_CTX *) ssl_ctx) {
      conn = ssl_conn[i];
      break;
    }
  }

  if (conn == NULL)
    return NULL;

  wpa_printf(MSG_DEBUG, "%s-i:%u", __func__, i);

  conn->ssl = CyaSSL_new((SSL_CTX *) ssl_ctx);
  if (conn->ssl == NULL) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Failed to initialize new SSL connection",
	       __func__);
    return NULL;
  }

/*   SSL_set_msg_callback(conn->ssl, tls_msg_cb); */
/*   SSL_set_msg_callback_arg(conn->ssl, conn); */

/*   options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | */
/*     SSL_OP_SINGLE_DH_USE; */
/* #ifdef SSL_OP_NO_COMPRESSION */
/*   options |= SSL_OP_NO_COMPRESSION; */
/* #endif /\* SSL_OP_NO_COMPRESSION *\/ */
/*   SSL_set_options(conn->ssl, options); */

  CyaSSL_UseSupportedCurve(conn->ssl, CYASSL_ECC_SECP256R1);
  CyaSSL_set_cipher_list(conn->ssl, "ECDHE-ECDSA-AES128-CCM-8");
  return conn;
}


void tls_connection_deinit(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return;
  SSL_free(conn->ssl);
  os_free(conn->subject_match);
  os_free(conn->altsubject_match);
  os_free(conn->suffix_match);
  os_free(conn->session_ticket);
  if (conn->ssl_in)
    wpabuf_free(conn->ssl_in);
  if (conn->ssl_out)
    wpabuf_free(conn->ssl_out);
  os_free(conn);
}


int tls_connection_established(void *ssl_ctx, struct tls_connection *conn)
{
  return conn ? SSL_is_init_finished(conn->ssl) : 0;
}


int tls_connection_shutdown(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return -1;

  /* Shutdown previous TLS connection without notifying the peer
   * because the connection was already terminated in practice
   * and "close notify" shutdown alert would confuse AS. */
  SSL_set_quiet_shutdown(conn->ssl, 1);
  SSL_shutdown(conn->ssl);
  return 0;
}


static int tls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  wpa_printf(MSG_DEBUG, "CyaSSL: verification fail");
  return preverify_ok;
}


static int tls_connection_ca_cert(void *_ssl_ctx, struct tls_connection *conn,
				  const char *ca_cert, const u8 *ca_cert_blob,
				  size_t ca_cert_blob_len, const char *ca_path)
{
  SSL_CTX *ssl_ctx = _ssl_ctx;

  SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, tls_verify_cb);
  conn->ca_cert_verify = 1;

  if (ca_cert && os_strncmp(ca_cert, "probe://", 8) == 0) {
    wpa_printf(MSG_DEBUG, "CyaSSL: Probe for server certificate "
	       "chain");
    conn->cert_probe = 1;
    conn->ca_cert_verify = 0;
    return 0;
  }

  if (ca_cert && os_strncmp(ca_cert, "hash://", 7) == 0) {
#ifdef CONFIG_SHA256
    const char *pos = ca_cert + 7;
    if (os_strncmp(pos, "server/sha256/", 14) != 0) {
      wpa_printf(MSG_DEBUG, "CyaSSL: Unsupported ca_cert "
		 "hash value '%s'", ca_cert);
      return -1;
    }
    pos += 14;
    if (os_strlen(pos) != 32 * 2) {
      wpa_printf(MSG_DEBUG, "CyaSSL: Unexpected SHA256 "
		 "hash length in ca_cert '%s'", ca_cert);
      return -1;
    }
    if (hexstr2bin(pos, conn->srv_cert_hash, 32) < 0) {
      wpa_printf(MSG_DEBUG, "CyaSSL: Invalid SHA256 hash "
		 "value in ca_cert '%s'", ca_cert);
      return -1;
    }
    conn->server_cert_only = 1;
    wpa_printf(MSG_DEBUG, "CyaSSL: Checking only server "
	       "certificate match");
    return 0;
#else /* CONFIG_SHA256 */
    wpa_printf(MSG_INFO, "No SHA256 included in the build - "
	       "cannot validate server certificate hash");
    return -1;
#endif /* CONFIG_SHA256 */
  }

  if (ca_cert_blob) {
    if (CyaSSL_CTX_load_verify_buffer(ssl_ctx,
				      ca_cert_blob,
				      ca_cert_blob_len,
				      SSL_FILETYPE_PEM) != SSL_SUCCESS &&
	CyaSSL_CTX_load_verify_buffer(ssl_ctx,
				      ca_cert_blob,
				      ca_cert_blob_len,
				      SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
      wpa_printf(MSG_WARNING,
		 "CyaSSL: %s - Failed to add ca_cert_blob to "
		 "certificate store", __func__);
    } else {
      wpa_printf(MSG_DEBUG, "TLS: Trusted root certificate(s) loaded");
      return 0;
    }
  }

  if (ca_cert || ca_path) {
#ifndef OPENSSL_NO_STDIO
    if (CyaSSL_CTX_load_verify_locations(ssl_ctx, ca_cert, ca_path)
	!= SSL_SUCCESS) {
      wpa_printf(MSG_WARNING,
		 "CyaSSL: %s - Failed to load root certificates", __func__);
      return -1;
    } else {
      wpa_printf(MSG_DEBUG, "TLS: Trusted root certificate(s) loaded");
      tls_get_errors(ssl_ctx);
    }
#else /* OPENSSL_NO_STDIO */
    wpa_printf(MSG_DEBUG, "CyaSSL: %s - OPENSSL_NO_STDIO",
	       __func__);
    return -1;
#endif /* OPENSSL_NO_STDIO */
  } else {
    /* No ca_cert configured - do not try to verify server
     * certificate */
    conn->ca_cert_verify = 0;
  }

  return 0;
}


static int tls_global_ca_cert(SSL_CTX *ssl_ctx, const char *ca_cert)
{
  if (ca_cert) {
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca_cert, NULL) != 1) {
      wpa_printf(MSG_WARNING,
		 "CyaSSL: %s - Failed to load root certificates", __func__);
      return -1;
    }

    wpa_printf(MSG_DEBUG, "TLS: Trusted root "
	       "certificate(s) loaded");

#ifndef OPENSSL_NO_STDIO
    /* Add the same CAs to the client certificate requests */
    SSL_CTX_set_client_CA_list(ssl_ctx,
			       SSL_load_client_CA_file(ca_cert));
#endif /* OPENSSL_NO_STDIO */
  }

  return 0;
}


int tls_global_set_verify(void *ssl_ctx, int check_crl)
{
  return 0;
}


static int tls_connection_set_subject_match(struct tls_connection *conn,
					    const char *subject_match,
					    const char *altsubject_match,
					    const char *suffix_match)
{
  os_free(conn->subject_match);
  conn->subject_match = NULL;
  if (subject_match) {
    conn->subject_match = os_strdup(subject_match);
    if (conn->subject_match == NULL)
      return -1;
  }

  os_free(conn->altsubject_match);
  conn->altsubject_match = NULL;
  if (altsubject_match) {
    conn->altsubject_match = os_strdup(altsubject_match);
    if (conn->altsubject_match == NULL)
      return -1;
  }

  os_free(conn->suffix_match);
  conn->suffix_match = NULL;
  if (suffix_match) {
    conn->suffix_match = os_strdup(suffix_match);
    if (conn->suffix_match == NULL)
      return -1;
  }

  return 0;
}


int tls_connection_set_verify(void *ssl_ctx, struct tls_connection *conn,
			      int verify_peer)
{
  static int counter = 0;

  if (conn == NULL)
    return -1;

  if (verify_peer) {
    conn->ca_cert_verify = 1;
    SSL_set_verify(conn->ssl, SSL_VERIFY_PEER |
		   SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
		   SSL_VERIFY_CLIENT_ONCE, tls_verify_cb);
  } else {
    conn->ca_cert_verify = 0;
    SSL_set_verify(conn->ssl, SSL_VERIFY_NONE, NULL);
  }

  SSL_set_accept_state(conn->ssl);

  /*
   * Set session id context in order to avoid fatal errors when client
   * tries to resume a session. However, set the context to a unique
   * value in order to effectively disable session resumption for now
   * since not all areas of the server code are ready for it (e.g.,
   * EAP-TTLS needs special handling for Phase 2 after abbreviated TLS
   * handshake).
   */
  counter++;
  SSL_set_session_id_context(conn->ssl,
			     (const unsigned char *) &counter,
			     sizeof(counter));

  return 0;
}


static int tls_connection_client_cert(struct tls_connection *conn,
				      const char *client_cert,
				      const u8 *client_cert_blob,
				      size_t client_cert_blob_len)
{
  if (client_cert_blob) {
    if (CyaSSL_use_certificate_buffer(conn->ssl,
				      client_cert_blob,
				      client_cert_blob_len,
				      SSL_FILETYPE_ASN1) == SSL_SUCCESS) {
      wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_ASN1 --> "
		 "OK");
      return 0;
    } else {
      wpa_printf(MSG_DEBUG,
		 "CyaSSL: %s - SSL_use_certificate_ASN1 failed", __func__);
    }
  }

  if (client_cert == NULL)
    return -1;

#ifndef OPENSSL_NO_STDIO
  if (CyaSSL_use_certificate_file(conn->ssl,
				  client_cert,
				  SSL_FILETYPE_ASN1) == SSL_SUCCESS) {
    wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_file (DER)"
	       " --> OK");
    return 0;
  }

  if (CyaSSL_use_certificate_chain_file(conn->ssl,
					client_cert) == SSL_SUCCESS) {
    ERR_clear_error();
    wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_chain_file (PEM)"
	       " --> OK");
    return 0;
  }

  if (CyaSSL_use_certificate_file(conn->ssl,
				  client_cert,
				  SSL_FILETYPE_PEM) == SSL_SUCCESS) {
    wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_file (PEM)"
	       " --> OK");
    return 0;
  }

  wpa_printf(MSG_DEBUG,
	     "CyaSSL: %s - SSL_use_certificate_file failed", __func__);
#else /* OPENSSL_NO_STDIO */
  wpa_printf(MSG_DEBUG, "CyaSSL: %s - OPENSSL_NO_STDIO", __func__);
#endif /* OPENSSL_NO_STDIO */

  return -1;
}


static int tls_global_client_cert(SSL_CTX *ssl_ctx, const char *client_cert)
{
#ifndef OPENSSL_NO_STDIO
  if (client_cert == NULL)
    return 0;

  if (CyaSSL_CTX_use_certificate_file(ssl_ctx,
				      client_cert,
				      SSL_FILETYPE_ASN1) != SSL_SUCCESS &&
      CyaSSL_CTX_use_certificate_chain_file(ssl_ctx,
					    client_cert) != SSL_SUCCESS &&
      CyaSSL_CTX_use_certificate_file(ssl_ctx,
				      client_cert,
				      SSL_FILETYPE_PEM) != SSL_SUCCESS) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Failed to load client certificate", __func__);
    return -1;
  }
  return 0;
#else /* OPENSSL_NO_STDIO */
  if (client_cert == NULL)
    return 0;
  wpa_printf(MSG_DEBUG, "CyaSSL: %s - OPENSSL_NO_STDIO", __func__);
  return -1;
#endif /* OPENSSL_NO_STDIO */
}


static int tls_passwd_cb(char *buf, int size, int rwflag, void *password)
{
  if (password == NULL) {
    return 0;
  }
  os_strlcpy(buf, (char *) password, size);
  return os_strlen(buf);
}


#ifdef PKCS12_FUNCS
static int tls_parse_pkcs12(SSL_CTX *ssl_ctx, SSL *ssl, PKCS12 *p12,
			    const char *passwd)
{
  EVP_PKEY *pkey;
  X509 *cert;
  STACK_OF(X509) *certs;
  int res = 0;
  char buf[256];

  pkey = NULL;
  cert = NULL;
  certs = NULL;
  if (!PKCS12_parse(p12, passwd, &pkey, &cert, &certs)) {
    wpa_printf(MSG_DEBUG, "CyaSSL: %s - Failed to parse PKCS12 file", __func__);
    PKCS12_free(p12);
    return -1;
  }
  wpa_printf(MSG_DEBUG, "TLS: Successfully parsed PKCS12 data");

  if (cert) {
    X509_NAME_oneline(X509_get_subject_name(cert), buf,
		      sizeof(buf));
    wpa_printf(MSG_DEBUG, "TLS: Got certificate from PKCS12: "
	       "subject='%s'", buf);
    if (ssl) {
      if (SSL_use_certificate(ssl, cert) != 1)
	res = -1;
    } else {
      if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1)
	res = -1;
    }
    X509_free(cert);
  }

  if (pkey) {
    wpa_printf(MSG_DEBUG, "TLS: Got private key from PKCS12");
    if (ssl) {
      if (SSL_use_PrivateKey(ssl, pkey) != 1)
	res = -1;
    } else {
      if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1)
	res = -1;
    }
    EVP_PKEY_free(pkey);
  }

  if (certs) {
    while ((cert = sk_X509_pop(certs)) != NULL) {
      X509_NAME_oneline(X509_get_subject_name(cert), buf,
			sizeof(buf));
      wpa_printf(MSG_DEBUG, "TLS: additional certificate"
		 " from PKCS12: subject='%s'", buf);
      /*
       * There is no SSL equivalent for the chain cert - so
       * always add it to the context...
       */
      if (SSL_CTX_add_extra_chain_cert(ssl_ctx, cert) != 1) {
	res = -1;
	break;
      }
    }
    sk_X509_free(certs);
  }

  PKCS12_free(p12);

  if (res < 0)
    tls_get_errors(ssl_ctx);

  return res;
}
#endif  /* PKCS12_FUNCS */


static int tls_read_pkcs12(SSL_CTX *ssl_ctx, SSL *ssl, const char *private_key,
			   const char *passwd)
{
#ifdef PKCS12_FUNCS
  FILE *f;
  PKCS12 *p12;

  f = fopen(private_key, "rb");
  if (f == NULL)
    return -1;

  p12 = d2i_PKCS12_fp(f, NULL);
  fclose(f);

  if (p12 == NULL) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Failed to use PKCS#12 file", __func__);
    return -1;
  }

  return tls_parse_pkcs12(ssl_ctx, ssl, p12, passwd);

#else /* PKCS12_FUNCS */
  wpa_printf(MSG_INFO, "TLS: PKCS12 support disabled - cannot read "
	     "p12/pfx files");
  return -1;
#endif  /* PKCS12_FUNCS */
}


static int tls_read_pkcs12_blob(SSL_CTX *ssl_ctx, SSL *ssl,
				const u8 *blob, size_t len, const char *passwd)
{
#ifdef PKCS12_FUNCS
  PKCS12 *p12;

  p12 = d2i_PKCS12(NULL, (OPENSSL_d2i_TYPE) &blob, len);
  if (p12 == NULL) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Failed to use PKCS#12 blob", __func__);
    return -1;
  }

  return tls_parse_pkcs12(ssl_ctx, ssl, p12, passwd);

#else /* PKCS12_FUNCS */
  wpa_printf(MSG_INFO, "TLS: PKCS12 support disabled - cannot parse "
	     "p12/pfx blobs");
  return -1;
#endif  /* PKCS12_FUNCS */
}

static int tls_connection_private_key(void *_ssl_ctx,
				      struct tls_connection *conn,
				      const char *private_key,
				      const char *private_key_passwd,
				      const u8 *private_key_blob,
				      size_t private_key_blob_len)
{
  SSL_CTX *ssl_ctx = _ssl_ctx;
  char *passwd;
  int ok;

  if (private_key == NULL && private_key_blob == NULL)
    return 0;

  if (private_key_passwd) {
    passwd = os_strdup(private_key_passwd);
    if (passwd == NULL)
      return -1;
  } else
    passwd = NULL;

  SSL_CTX_set_default_passwd_cb(ssl_ctx, tls_passwd_cb);
  SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, passwd);

  ok = 0;
  while (private_key_blob) {
    if (CyaSSL_use_PrivateKey_buffer(conn->ssl,
				     private_key_blob,
				     private_key_blob_len,
				     SSL_FILETYPE_ASN1) == SSL_SUCCESS) {
      wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_PrivateKey_"
		 "ASN1 --> OK");
      ok = 1;
      break;
    }

    if (CyaSSL_use_PrivateKey_buffer(conn->ssl,
				     private_key_blob,
				     private_key_blob_len,
				     SSL_FILETYPE_PEM) == SSL_SUCCESS) {
      wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_PrivateKey_"
		 "PEM --> OK");
      ok = 1;
      break;
    }

    if (tls_read_pkcs12_blob(ssl_ctx, conn->ssl, private_key_blob,
			     private_key_blob_len, passwd) == 0) {
      wpa_printf(MSG_DEBUG, "CyaSSL: PKCS#12 as blob --> "
		 "OK");
      ok = 1;
      break;
    }

    break;
  }

  while (!ok && private_key) {
#ifndef OPENSSL_NO_STDIO
    if (CyaSSL_use_PrivateKey_file(conn->ssl,
				   private_key,
				   SSL_FILETYPE_ASN1) == 1) {
      wpa_printf(MSG_DEBUG, "CyaSSL: "
		 "SSL_use_PrivateKey_File (DER) --> OK");
      ok = 1;
      break;
    }

    if (CyaSSL_use_PrivateKey_file(conn->ssl,
				   private_key,
				   SSL_FILETYPE_PEM) == 1) {
      wpa_printf(MSG_DEBUG, "CyaSSL: "
		 "SSL_use_PrivateKey_File (PEM) --> OK");
      ok = 1;
      break;
    }
#else /* OPENSSL_NO_STDIO */
    wpa_printf(MSG_DEBUG, "CyaSSL: %s - OPENSSL_NO_STDIO",
	       __func__);
#endif /* OPENSSL_NO_STDIO */

    if (tls_read_pkcs12(ssl_ctx, conn->ssl, private_key, passwd)
	== 0) {
      wpa_printf(MSG_DEBUG, "CyaSSL: Reading PKCS#12 file "
		 "--> OK");
      ok = 1;
      break;
    }

    break;
  }

  if (!ok) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Failed to load private key", __func__);
    os_free(passwd);
    return -1;
  }
  ERR_clear_error();
  SSL_CTX_set_default_passwd_cb(ssl_ctx, NULL);
  os_free(passwd);

  if (!CyaSSL_CTX_check_private_key(conn->ssl_ctx)) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Private key failed verification", __func__);
    return -1;
  }

  wpa_printf(MSG_DEBUG, "SSL: Private key loaded successfully");
  return 0;
}


static int tls_global_private_key(SSL_CTX *ssl_ctx, const char *private_key,
				  const char *private_key_passwd)
{
  char *passwd;

  if (private_key == NULL)
    return 0;

  if (private_key_passwd) {
    passwd = os_strdup(private_key_passwd);
    if (passwd == NULL)
      return -1;
  } else
    passwd = NULL;

  SSL_CTX_set_default_passwd_cb(ssl_ctx, tls_passwd_cb);
  SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, passwd);
  if (
#ifndef OPENSSL_NO_STDIO
      SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key,
				  SSL_FILETYPE_ASN1) != 1 &&
      SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key,
				  SSL_FILETYPE_PEM) != 1 &&
#endif /* OPENSSL_NO_STDIO */
      tls_read_pkcs12(ssl_ctx, NULL, private_key, passwd)) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Failed to load private key", __func__);
    os_free(passwd);
    ERR_clear_error();
    return -1;
  }
  os_free(passwd);
  ERR_clear_error();
  SSL_CTX_set_default_passwd_cb(ssl_ctx, NULL);

  if (!SSL_CTX_check_private_key(ssl_ctx)) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Private key failed verification", __func__);
    return -1;
  }

  return 0;
}

int tls_connection_get_keys(void *ssl_ctx, struct tls_connection *conn,
			    struct tls_keys *keys)
{
  return -1;
}


int tls_connection_prf(void *tls_ctx, struct tls_connection *conn,
		       const char *label, int server_random_first,
		       u8 *out, size_t out_len)
{
  if (conn == NULL)
    return -1;
  if (server_random_first)
    return -1;

  if (CyaSSL_make_eap_keys(conn->ssl, out, out_len, label) == 0) {
    wpa_printf(MSG_DEBUG, "CyaSSL: Using internal PRF");
    return 0;
  }

  return -1;
}

static struct wpabuf *
cyassl_handshake(struct tls_connection *conn, const struct wpabuf *in_data,
		  int server)
{
  int res;
  struct wpabuf *out_data;

  /*
   * Give TLS handshake data from the server (if available) to CyaSSL
   * for processing.
   */
  wpa_printf(MSG_DEBUG, "%s-conn:%p, conn>ssl:%p, conn->ssl_in:%p, "
	     "in_data:%p(%u byte), server:%d",
	     __func__, conn, conn->ssl, conn->ssl_in,
	     in_data, wpabuf_len(in_data), server);

  if (conn->ssl_in)
    wpabuf_free(conn->ssl_in);

  conn->ssl_in = wpabuf_dup(in_data);
  if (!conn->ssl_in) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Handshake failed - BIO_write", __func__);
    return NULL;
  }

  /* Initiate TLS handshake or continue the existing handshake */
  if (server)
    res = CyaSSL_accept(conn->ssl);
  else
    res = CyaSSL_connect(conn->ssl);

  if (res != 1) {
    int err = CyaSSL_get_error(conn->ssl, res);
    if (err == SSL_ERROR_WANT_READ)
      wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want "
		 "more data");
    else if (err == SSL_ERROR_WANT_WRITE)
      wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want to "
		 "write");
    else {
      wpa_printf(MSG_INFO, "CyaSSL: %s - SSL_connect", __func__);
      conn->failed++;
    }
  }

  /* Get the TLS handshake data to be sent to the server */
  if (conn->ssl_out) {
    res = wpabuf_len(conn->ssl_out);
    out_data = wpabuf_dup(conn->ssl_out);
    wpabuf_free(conn->ssl_out);
    conn->ssl_out = NULL;
  } else {
    res = 0;
    out_data = wpabuf_alloc(0);
  }

  wpa_printf(MSG_DEBUG, "SSL: %d bytes pending from ssl_out",
	     res);

  if (out_data == NULL) {
    wpa_printf(MSG_DEBUG, "SSL: Failed to allocate memory for "
	       "handshake output (%d bytes)", res);
    return NULL;
  }

  return out_data;
}


static struct wpabuf *
openssl_get_appl_data(struct tls_connection *conn, size_t max_len)
{
  struct wpabuf *appl_data;
  int res;

  appl_data = wpabuf_alloc(max_len + 100);
  if (appl_data == NULL)
    return NULL;

  res = SSL_read(conn->ssl, wpabuf_mhead(appl_data),
		 wpabuf_size(appl_data));
  if (res < 0) {
    int err = SSL_get_error(conn->ssl, res);
    if (err == SSL_ERROR_WANT_READ ||
	err == SSL_ERROR_WANT_WRITE) {
      wpa_printf(MSG_DEBUG, "SSL: No Application Data "
		 "included");
    } else {
      wpa_printf(MSG_INFO, "CyaSSL: %s - Failed to read possible "
		 "Application Data", __func__);
    }
    wpabuf_free(appl_data);
    return NULL;
  }

  wpabuf_put(appl_data, res);
  wpa_hexdump_buf_key(MSG_MSGDUMP, "SSL: Application Data in Finished "
		      "message", appl_data);

  return appl_data;
}


static struct wpabuf *
cyassl_connection_handshake(struct tls_connection *conn,
			     const struct wpabuf *in_data,
			     struct wpabuf **appl_data, int server)
{
  struct wpabuf *out_data;

  if (appl_data)
    *appl_data = NULL;

  out_data = cyassl_handshake(conn, in_data, server);
  if (out_data == NULL)
    return NULL;
  if (conn->invalid_hb_used) {
    wpa_printf(MSG_INFO, "TLS: Heartbeat attack detected - do not send response");
    wpabuf_free(out_data);
    return NULL;
  }

  if (SSL_is_init_finished(conn->ssl) && appl_data && in_data)
    *appl_data = openssl_get_appl_data(conn, wpabuf_len(in_data));

  if (conn->invalid_hb_used) {
    wpa_printf(MSG_INFO, "TLS: Heartbeat attack detected - do not send response");
    if (appl_data) {
      wpabuf_free(*appl_data);
      *appl_data = NULL;
    }
    wpabuf_free(out_data);
    return NULL;
  }

  return out_data;
}


struct wpabuf *
tls_connection_handshake(void *ctx, struct tls_connection *conn,
			 const struct wpabuf *in_data,
			 struct wpabuf **appl_data)
{
  return cyassl_connection_handshake(conn, in_data, appl_data, 0);
}


struct wpabuf * tls_connection_server_handshake(void *ctx,
						struct tls_connection *conn,
						const struct wpabuf *in_data,
						struct wpabuf **appl_data)
{
  return cyassl_connection_handshake(conn, in_data, appl_data, 1);
}


struct wpabuf * tls_connection_encrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
  int res;
  struct wpabuf *buf;

  if (conn == NULL)
    return NULL;

  /* Give plaintext data for CyaSSL to encrypt into the TLS tunnel. */
  if (conn->ssl_in) {
    wpabuf_free(conn->ssl_in);
    conn->ssl_in = NULL;
  }

  if (conn->ssl_out) {
    wpabuf_free(conn->ssl_out);
    conn->ssl_out = NULL;
  }

  res = CyaSSL_write(conn->ssl, wpabuf_head(in_data), wpabuf_len(in_data));
  if (res < 0) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Encryption failed - SSL_write", __func__);
    return NULL;
  }

  /* Read encrypted data to be sent to the server */
  if (!conn->ssl_out) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - No ssl_out", __func__);
    return NULL;
  }

  buf = wpabuf_dup(conn->ssl_out);
  if (buf == NULL) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Out of memory", __func__);
    return NULL;
  }

  wpabuf_free(conn->ssl_out);
  conn->ssl_out = NULL;
  return buf;
}


struct wpabuf * tls_connection_decrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
  int res;
  struct wpabuf *buf;

  /* Give encrypted data from TLS tunnel for CyaSSL to decrypt. */
  if (conn->ssl_in) {
    wpabuf_free(conn->ssl_in);
  }

  if (conn->ssl_out) {
    wpabuf_free(conn->ssl_out);
  }

  conn->ssl_in = wpabuf_dup(in_data);
  if (!conn->ssl_in) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Out of memory", __func__);
    return NULL;
  }

  /* Read decrypted data for further processing */
  /*
   * Even though we try to disable TLS compression, it is possible that
   * this cannot be done with all TLS libraries. Add extra buffer space
   * to handle the possibility of the decrypted data being longer than
   * input data.
   */
  buf = wpabuf_alloc((wpabuf_len(in_data) + 500) * 3);
  if (buf == NULL) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - out of memory", __func__);
    return NULL;
  }

  res = CyaSSL_read(conn->ssl, wpabuf_mhead(buf), wpabuf_size(buf));
  if (res < 0) {
    wpa_printf(MSG_INFO, "CyaSSL: %s - Decryption failed - SSL_read", __func__);
    wpabuf_free(buf);
    return NULL;
  }
  wpabuf_put(buf, res);

  if (conn->invalid_hb_used) {
    wpa_printf(MSG_INFO, "TLS: Heartbeat attack detected - do not send response");
    wpabuf_free(buf);
    return NULL;
  }

  return buf;
}


int tls_connection_resumed(void *ssl_ctx, struct tls_connection *conn)
{
  /*
   * This function seems to be used by only TTLS and PEAP. Since we only target
   * for EAP-TLS, we made it to return 0.
   */
  return 0;
}


int tls_connection_set_cipher_list(void *tls_ctx, struct tls_connection *conn,
				   u8 *ciphers)
{
  char buf[100], *pos, *end;
  u8 *c;
  int ret;

  if (conn == NULL || conn->ssl == NULL || ciphers == NULL)
    return -1;

  buf[0] = '\0';
  pos = buf;
  end = pos + sizeof(buf);

  c = ciphers;
  while (*c != TLS_CIPHER_NONE) {
    const char *suite;

    switch (*c) {
    case TLS_CIPHER_RC4_SHA:
      suite = "RC4-SHA";
      break;
    case TLS_CIPHER_AES128_SHA:
      suite = "AES128-SHA";
      break;
    case TLS_CIPHER_RSA_DHE_AES128_SHA:
      suite = "DHE-RSA-AES128-SHA";
      break;
    case TLS_CIPHER_ANON_DH_AES128_SHA:
      suite = "ADH-AES128-SHA";
      break;
    default:
      wpa_printf(MSG_DEBUG, "TLS: Unsupported "
		 "cipher selection: %d", *c);
      return -1;
    }
    ret = os_snprintf(pos, end - pos, ":%s", suite);
    if (ret < 0 || ret >= end - pos)
      break;
    pos += ret;

    c++;
  }

  wpa_printf(MSG_DEBUG, "CyaSSL: cipher suites: %s", buf + 1);

  if (SSL_set_cipher_list(conn->ssl, buf + 1) != 1) {
    wpa_printf(MSG_INFO,
	       "CyaSSL: %s - Cipher suite configuration failed", __func__);
    return -1;
  }

  return 0;
}


int tls_get_cipher(void *ssl_ctx, struct tls_connection *conn,
		   char *buf, size_t buflen)
{
  const char *name;
  if (conn == NULL || conn->ssl == NULL)
    return -1;

  name = SSL_get_cipher(conn->ssl);
  if (name == NULL)
    return -1;

  os_strlcpy(buf, name, buflen);
  return 0;
}


int tls_connection_enable_workaround(void *ssl_ctx,
				     struct tls_connection *conn)
{
  /* SSL_set_options(conn->ssl, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS); */

  return 0;
}

int tls_connection_get_failed(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return -1;
  return conn->failed;
}


int tls_connection_get_read_alerts(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return -1;
  return conn->read_alerts;
}


int tls_connection_get_write_alerts(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return -1;
  return conn->write_alerts;
}

int tls_connection_set_params(void *tls_ctx, struct tls_connection *conn,
			      const struct tls_connection_params *params)
{
  if (conn == NULL)
    return -1;

  if (tls_connection_set_subject_match(conn,
				       params->subject_match,
				       params->altsubject_match,
				       params->suffix_match))
    return -1;

  if (tls_connection_ca_cert(tls_ctx, conn, params->ca_cert,
			     params->ca_cert_blob,
			     params->ca_cert_blob_len,
			     params->ca_path))
    return -1;

  if (tls_connection_client_cert(conn, params->client_cert,
				 params->client_cert_blob,
				 params->client_cert_blob_len))
    return -1;

  if (tls_connection_private_key(tls_ctx, conn,
				 params->private_key,
				 params->private_key_passwd,
				 params->private_key_blob,
				 params->private_key_blob_len)) {
    wpa_printf(MSG_INFO, "TLS: Failed to load private key '%s'",
	       params->private_key);
    return -1;
  }

  if (params->dh_file) {
    wpa_printf(MSG_INFO, "TLS: Failed to load DH file '%s'",
	       params->dh_file);
    return -1;
  }

#ifdef SSL_OP_NO_TICKET
  if (params->flags & TLS_CONN_DISABLE_SESSION_TICKET)
    SSL_set_options(conn->ssl, SSL_OP_NO_TICKET);
#ifdef SSL_clear_options
  else
    SSL_clear_options(conn->ssl, SSL_OP_NO_TICKET);
#endif /* SSL_clear_options */
#endif /*  SSL_OP_NO_TICKET */

#ifdef SSL_OP_NO_TLSv1_1
  if (params->flags & TLS_CONN_DISABLE_TLSv1_1)
    SSL_set_options(conn->ssl, SSL_OP_NO_TLSv1_1);
  else
    SSL_clear_options(conn->ssl, SSL_OP_NO_TLSv1_1);
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
  if (params->flags & TLS_CONN_DISABLE_TLSv1_2)
    SSL_set_options(conn->ssl, SSL_OP_NO_TLSv1_2);
  else
    SSL_clear_options(conn->ssl, SSL_OP_NO_TLSv1_2);
#endif /* SSL_OP_NO_TLSv1_2 */

  conn->flags = params->flags;

  tls_get_errors(tls_ctx);

  return 0;
}


int tls_global_set_params(void *tls_ctx,
			  const struct tls_connection_params *params)
{
  SSL_CTX *ssl_ctx = tls_ctx;
  unsigned long err;

  while ((err = ERR_get_error())) {
    wpa_printf(MSG_INFO, "%s: Clearing pending SSL error: %s",
	       __func__, ERR_error_string(err, NULL));
  }

  if (tls_global_ca_cert(ssl_ctx, params->ca_cert))
    return -1;

  if (tls_global_client_cert(ssl_ctx, params->client_cert))
    return -1;

  if (tls_global_private_key(ssl_ctx, params->private_key,
			     params->private_key_passwd))
    return -1;

  if (params->dh_file) {
    wpa_printf(MSG_INFO, "TLS: Failed to load DH file '%s'",
	       params->dh_file);
    return -1;
  }

#ifdef SSL_OP_NO_TICKET
  if (params->flags & TLS_CONN_DISABLE_SESSION_TICKET)
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
#ifdef SSL_CTX_clear_options
  else
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TICKET);
#endif /* SSL_clear_options */
#endif /*  SSL_OP_NO_TICKET */

  return 0;
}


int tls_connection_get_keyblock_size(void *_tls_ctx,
				     struct tls_connection *conn)
{
/*   CYASSL_CTX *tls_ctx = _tls_ctx; */
/*   const EVP_CIPHER *c; */
/*   const EVP_MD *h; */
/*   int md_size; */

/*   if (conn == NULL || conn->ssl == NULL || */
/*       conn->ssl->enc_read_ctx == NULL || */
/*       conn->ssl->enc_read_ctx->cipher == NULL || */
/*       conn->ssl->read_hash == NULL) */
/*     return -1; */

/*   //c = conn->ssl->enc_read_ctx->cipher; */
/*   c = tls_ctx->cipherType; */
/* #if OPENSSL_VERSION_NUMBER >= 0x00909000L */
/*   h = EVP_MD_CTX_md(conn->ssl->read_hash); */
/* #else */
/*   h = conn->ssl->read_hash; */
/* #endif */
/*   if (h) */
/*     md_size = EVP_MD_size(h); */
/* #if OPENSSL_VERSION_NUMBER >= 0x10000000L */
/*   else if (conn->ssl->s3) */
/*     md_size = conn->ssl->s3->tmp.new_mac_secret_size; */
/* #endif */
/*   else */
/*     return -1; */

/*   wpa_printf(MSG_DEBUG, "OpenSSL: keyblock size: key_len=%d MD_size=%d " */
/* 	     "IV_len=%d", EVP_CIPHER_key_length(c), md_size, */
/* 	     EVP_CIPHER_iv_length(c)); */
/*   return 2 * (EVP_CIPHER_key_length(c) + */
/* 	      md_size + */
/* 	      EVP_CIPHER_iv_length(c)); */
  return -1;
}


unsigned int tls_capabilities(void *tls_ctx)
{
  return 0;
}


int tls_connection_set_session_ticket_cb(void *tls_ctx,
					 struct tls_connection *conn,
					 tls_session_ticket_cb cb,
					 void *ctx)
{
  return -1;
}
