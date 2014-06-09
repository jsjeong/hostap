/*
 * SSL/TLS interface functions for OpenSSL
 * Copyright (c) 2004-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

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

  CYASSL_X509_STORE *cert_store;
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

static void tls_show_errors(int level, const char *func, const char *txt)
{
  unsigned long err;

  wpa_printf(level, "CyaSSL: %s - %s %s",
	     func, txt, ERR_error_string(ERR_get_error(), NULL));

  while ((err = ERR_get_error())) {
    wpa_printf(MSG_INFO, "CyaSSL: pending error: %s",
	       ERR_error_string(err, NULL));
  }
}

/* static void ssl_info_cb(const SSL *ssl, int where, int ret) */
/* { */
/* 	const char *str; */
/* 	int w; */

/* 	wpa_printf(MSG_DEBUG, "SSL: (where=0x%x ret=0x%x)", where, ret); */
/* 	w = where & ~SSL_ST_MASK; */
/* 	if (w & SSL_ST_CONNECT) */
/* 		str = "SSL_connect"; */
/* 	else if (w & SSL_ST_ACCEPT) */
/* 		str = "SSL_accept"; */
/* 	else */
/* 		str = "undefined"; */

/* 	if (where & SSL_CB_LOOP) { */
/* 		wpa_printf(MSG_DEBUG, "SSL: %s:%s", */
/* 			   str, SSL_state_string_long(ssl)); */
/* 	} else if (where & SSL_CB_ALERT) { */
/* 		struct tls_connection *conn = SSL_get_app_data((SSL *) ssl); */
/* 		wpa_printf(MSG_INFO, "SSL: SSL3 alert: %s:%s:%s", */
/* 			   where & SSL_CB_READ ? */
/* 			   "read (remote end reported an error)" : */
/* 			   "write (local SSL3 detected an error)", */
/* 			   SSL_alert_type_string_long(ret), */
/* 			   SSL_alert_desc_string_long(ret)); */
/* 		if ((ret >> 8) == SSL3_AL_FATAL) { */
/* 			if (where & SSL_CB_READ) */
/* 				conn->read_alerts++; */
/* 			else */
/* 				conn->write_alerts++; */
/* 		} */
/* 		if (conn->context->event_cb != NULL) { */
/* 			union tls_event_data ev; */
/* 			struct tls_context *context = conn->context; */
/* 			os_memset(&ev, 0, sizeof(ev)); */
/* 			ev.alert.is_local = !(where & SSL_CB_READ); */
/* 			ev.alert.type = SSL_alert_type_string_long(ret); */
/* 			ev.alert.description = SSL_alert_desc_string_long(ret); */
/* 			context->event_cb(context->cb_ctx, TLS_ALERT, &ev); */
/* 		} */
/* 	} else if (where & SSL_CB_EXIT && ret <= 0) { */
/* 		wpa_printf(MSG_DEBUG, "SSL: %s:%s in %s", */
/* 			   str, ret == 0 ? "failed" : "error", */
/* 			   SSL_state_string_long(ssl)); */
/* 	} */
/* } */

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

    //CyaSSL_Debugging_ON();
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
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();
    EVP_cleanup();
    os_free(tls_global->ocsp_stapling_response);
    tls_global->ocsp_stapling_response = NULL;
    os_free(tls_global);
    tls_global = NULL;
  }
}



int tls_get_errors(void *ssl_ctx)
{
  int count = 0;
  unsigned long err;

  while ((err = ERR_get_error())) {
    wpa_printf(MSG_INFO, "TLS - SSL error: %s",
	       ERR_error_string(err, NULL));
    count++;
  }

  return count;
}


static void tls_msg_cb(int write_p, int version, int content_type,
		       const void *buf, size_t len, SSL *ssl, void *arg)
{
  struct tls_connection *conn = arg;
  const u8 *pos = buf;

  wpa_printf(MSG_DEBUG, "CyaSSL: %s ver=0x%x content_type=%d",
	     write_p ? "TX" : "RX", version, content_type);
  wpa_hexdump_key(MSG_MSGDUMP, "CyaSSL: Message", buf, len);
  if (content_type == 24 && len >= 3 && pos[0] == 1) {
    size_t payload_len = WPA_GET_BE16(pos + 1);
    if (payload_len + 3 > len) {
      wpa_printf(MSG_ERROR, "CyaSSL: Heartbeat attack detected");
      conn->invalid_hb_used = 1;
    }
  }
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
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to initialize new SSL connection");
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

  return conn;
}


void tls_connection_deinit(void *ssl_ctx, struct tls_connection *conn)
{
  if (conn == NULL)
    return;
  SSL_free(conn->ssl);
  CyaSSL_X509_STORE_free(conn->cert_store);
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


/* static int tls_match_altsubject_component(X509 *cert, int type, */
/* 					  const char *value, size_t len) */
/* { */
/*   GENERAL_NAME *gen; */
/*   void *ext; */
/*   int i, found = 0; */

/*   ext = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL); */

/*   for (i = 0; ext && i < sk_GENERAL_NAME_num(ext); i++) { */
/*     gen = sk_GENERAL_NAME_value(ext, i); */
/*     if (gen->type != type) */
/*       continue; */
/*     if (os_strlen((char *) gen->d.ia5->data) == len && */
/* 	os_memcmp(value, gen->d.ia5->data, len) == 0) */
/*       found++; */
/*   } */

/*   return found; */
/* } */


/* static int tls_match_altsubject(X509 *cert, const char *match) */
/* { */
/*   int type; */
/*   const char *pos, *end; */
/*   size_t len; */

/*   pos = match; */
/*   do { */
/*     if (os_strncmp(pos, "EMAIL:", 6) == 0) { */
/*       type = GEN_EMAIL; */
/*       pos += 6; */
/*     } else if (os_strncmp(pos, "DNS:", 4) == 0) { */
/*       type = GEN_DNS; */
/*       pos += 4; */
/*     } else if (os_strncmp(pos, "URI:", 4) == 0) { */
/*       type = GEN_URI; */
/*       pos += 4; */
/*     } else { */
/*       wpa_printf(MSG_INFO, "TLS: Invalid altSubjectName " */
/* 		 "match '%s'", pos); */
/*       return 0; */
/*     } */
/*     end = os_strchr(pos, ';'); */
/*     while (end) { */
/*       if (os_strncmp(end + 1, "EMAIL:", 6) == 0 || */
/* 	  os_strncmp(end + 1, "DNS:", 4) == 0 || */
/* 	  os_strncmp(end + 1, "URI:", 4) == 0) */
/* 	break; */
/*       end = os_strchr(end + 1, ';'); */
/*     } */
/*     if (end) */
/*       len = end - pos; */
/*     else */
/*       len = os_strlen(pos); */
/*     if (tls_match_altsubject_component(cert, type, pos, len) > 0) */
/*       return 1; */
/*     pos = end + 1; */
/*   } while (end); */

/*   return 0; */
/* } */


/* #ifndef CONFIG_NATIVE_WINDOWS */
/* static int domain_suffix_match(const u8 *val, size_t len, const char *match) */
/* { */
/*   size_t i, match_len; */

/*   /\* Check for embedded nuls that could mess up suffix matching *\/ */
/*   for (i = 0; i < len; i++) { */
/*     if (val[i] == '\0') { */
/*       wpa_printf(MSG_DEBUG, "TLS: Embedded null in a string - reject"); */
/*       return 0; */
/*     } */
/*   } */

/*   match_len = os_strlen(match); */
/*   if (match_len > len) */
/*     return 0; */

/*   if (os_strncasecmp((const char *) val + len - match_len, match, */
/* 		     match_len) != 0) */
/*     return 0; /\* no match *\/ */

/*   if (match_len == len) */
/*     return 1; /\* exact match *\/ */

/*   if (val[len - match_len - 1] == '.') */
/*     return 1; /\* full label match completes suffix match *\/ */

/*   wpa_printf(MSG_DEBUG, "TLS: Reject due to incomplete label match"); */
/*   return 0; */
/* } */
/* #endif /\* CONFIG_NATIVE_WINDOWS *\/ */


/* static int tls_match_suffix(X509 *cert, const char *match) */
/* { */
/* #ifdef CONFIG_NATIVE_WINDOWS */
/*   /\* wincrypt.h has conflicting X509_NAME definition *\/ */
/*   return -1; */
/* #else /\* CONFIG_NATIVE_WINDOWS *\/ */
/*   GENERAL_NAME *gen; */
/*   void *ext; */
/*   int i; */
/*   int dns_name = 0; */
/*   X509_NAME *name; */

/*   wpa_printf(MSG_DEBUG, "TLS: Match domain against suffix %s", match); */

/*   ext = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL); */

/*   for (i = 0; ext && i < sk_GENERAL_NAME_num(ext); i++) { */
/*     gen = sk_GENERAL_NAME_value(ext, i); */
/*     if (gen->type != GEN_DNS) */
/*       continue; */
/*     dns_name++; */
/*     wpa_hexdump_ascii(MSG_DEBUG, "TLS: Certificate dNSName", */
/* 		      gen->d.dNSName->data, */
/* 		      gen->d.dNSName->length); */
/*     if (domain_suffix_match(gen->d.dNSName->data, */
/* 			    gen->d.dNSName->length, match) == 1) { */
/*       wpa_printf(MSG_DEBUG, "TLS: Suffix match in dNSName found"); */
/*       return 1; */
/*     } */
/*   } */

/*   if (dns_name) { */
/*     wpa_printf(MSG_DEBUG, "TLS: None of the dNSName(s) matched"); */
/*     return 0; */
/*   } */

/*   name = X509_get_subject_name(cert); */
/*   i = -1; */
/*   for (;;) { */
/*     X509_NAME_ENTRY *e; */
/*     ASN1_STRING *cn; */

/*     i = X509_NAME_get_index_by_NID(name, NID_commonName, i); */
/*     if (i == -1) */
/*       break; */
/*     e = X509_NAME_get_entry(name, i); */
/*     if (e == NULL) */
/*       continue; */
/*     cn = X509_NAME_ENTRY_get_data(e); */
/*     if (cn == NULL) */
/*       continue; */
/*     wpa_hexdump_ascii(MSG_DEBUG, "TLS: Certificate commonName", */
/* 		      cn->data, cn->length); */
/*     if (domain_suffix_match(cn->data, cn->length, match) == 1) { */
/*       wpa_printf(MSG_DEBUG, "TLS: Suffix match in commonName found"); */
/*       return 1; */
/*     } */
/*   } */

/*   wpa_printf(MSG_DEBUG, "TLS: No CommonName suffix match found"); */
/*   return 0; */
/* #endif /\* CONFIG_NATIVE_WINDOWS *\/ */
/* } */


/* static enum tls_fail_reason openssl_tls_fail_reason(int err) */
/* { */
/*   switch (err) { */
/*   case X509_V_ERR_CERT_REVOKED: */
/*     return TLS_FAIL_REVOKED; */
/*   case X509_V_ERR_CERT_NOT_YET_VALID: */
/*   case X509_V_ERR_CRL_NOT_YET_VALID: */
/*     return TLS_FAIL_NOT_YET_VALID; */
/*   case X509_V_ERR_CERT_HAS_EXPIRED: */
/*   case X509_V_ERR_CRL_HAS_EXPIRED: */
/*     return TLS_FAIL_EXPIRED; */
/*   case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: */
/*   case X509_V_ERR_UNABLE_TO_GET_CRL: */
/*   case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: */
/*   case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: */
/*   case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: */
/*   case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: */
/*   case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: */
/*   case X509_V_ERR_CERT_CHAIN_TOO_LONG: */
/*   case X509_V_ERR_PATH_LENGTH_EXCEEDED: */
/*   case X509_V_ERR_INVALID_CA: */
/*     return TLS_FAIL_UNTRUSTED; */
/*   case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: */
/*   case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: */
/*   case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: */
/*   case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: */
/*   case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: */
/*   case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: */
/*   case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: */
/*   case X509_V_ERR_CERT_UNTRUSTED: */
/*   case X509_V_ERR_CERT_REJECTED: */
/*     return TLS_FAIL_BAD_CERTIFICATE; */
/*   default: */
/*     return TLS_FAIL_UNSPECIFIED; */
/*   } */
/* } */


/* static struct wpabuf * get_x509_cert(X509 *cert) */
/* { */
/*   struct wpabuf *buf; */
/*   u8 *tmp; */

/*   int cert_len = i2d_X509(cert, NULL); */
/*   if (cert_len <= 0) */
/*     return NULL; */

/*   buf = wpabuf_alloc(cert_len); */
/*   if (buf == NULL) */
/*     return NULL; */

/*   tmp = wpabuf_put(buf, cert_len); */
/*   i2d_X509(cert, &tmp); */
/*   return buf; */
/* } */


/* static void openssl_tls_fail_event(struct tls_connection *conn, */
/* 				   X509 *err_cert, int err, int depth, */
/* 				   const char *subject, const char *err_str, */
/* 				   enum tls_fail_reason reason) */
/* { */
/*   union tls_event_data ev; */
/*   struct wpabuf *cert = NULL; */
/*   struct tls_context *context = conn->context; */

/*   if (context->event_cb == NULL) */
/*     return; */

/*   cert = get_x509_cert(err_cert); */
/*   os_memset(&ev, 0, sizeof(ev)); */
/*   ev.cert_fail.reason = reason != TLS_FAIL_UNSPECIFIED ? */
/*     reason : openssl_tls_fail_reason(err); */
/*   ev.cert_fail.depth = depth; */
/*   ev.cert_fail.subject = subject; */
/*   ev.cert_fail.reason_txt = err_str; */
/*   ev.cert_fail.cert = cert; */
/*   context->event_cb(context->cb_ctx, TLS_CERT_CHAIN_FAILURE, &ev); */
/*   wpabuf_free(cert); */
/* } */


/* static void openssl_tls_cert_event(struct tls_connection *conn, */
/* 				   X509 *err_cert, int depth, */
/* 				   const char *subject) */
/* { */
/*   struct wpabuf *cert = NULL; */
/*   union tls_event_data ev; */
/*   struct tls_context *context = conn->context; */
/* #ifdef CONFIG_SHA256 */
/*   u8 hash[32]; */
/* #endif /\* CONFIG_SHA256 *\/ */

/*   if (context->event_cb == NULL) */
/*     return; */

/*   os_memset(&ev, 0, sizeof(ev)); */
/*   if (conn->cert_probe || context->cert_in_cb) { */
/*     cert = get_x509_cert(err_cert); */
/*     ev.peer_cert.cert = cert; */
/*   } */
/* #ifdef CONFIG_SHA256 */
/*   if (cert) { */
/*     const u8 *addr[1]; */
/*     size_t len[1]; */
/*     addr[0] = wpabuf_head(cert); */
/*     len[0] = wpabuf_len(cert); */
/*     if (sha256_vector(1, addr, len, hash) == 0) { */
/*       ev.peer_cert.hash = hash; */
/*       ev.peer_cert.hash_len = sizeof(hash); */
/*     } */
/*   } */
/* #endif /\* CONFIG_SHA256 *\/ */
/*   ev.peer_cert.depth = depth; */
/*   ev.peer_cert.subject = subject; */
/*   context->event_cb(context->cb_ctx, TLS_PEER_CERTIFICATE, &ev); */
/*   wpabuf_free(cert); */
/* } */


static int tls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
/*   char buf[256]; */
/*   X509 *err_cert; */
/*   int err, depth; */
/*   SSL *ssl; */
/*   struct tls_connection *conn; */
/*   struct tls_context *context; */
/*   char *match, *altmatch, *suffix_match; */
/*   const char *err_str; */

/*   err_cert = X509_STORE_CTX_get_current_cert(x509_ctx); */
/*   if (!err_cert) */
/*     return 0; */

/*   err = X509_STORE_CTX_get_error(x509_ctx); */
/*   depth = X509_STORE_CTX_get_error_depth(x509_ctx); */
/*   ssl = X509_STORE_CTX_get_ex_data(x509_ctx, */
/* 				   SSL_get_ex_data_X509_STORE_CTX_idx()); */
/*   X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf)); */

/*   conn = SSL_get_app_data(ssl); */
/*   if (conn == NULL) */
/*     return 0; */

/*   if (depth == 0) */
/*     conn->peer_cert = err_cert; */
/*   else if (depth == 1) */
/*     conn->peer_issuer = err_cert; */
/*   else if (depth == 2) */
/*     conn->peer_issuer_issuer = err_cert; */

/*   context = conn->context; */
/*   match = conn->subject_match; */
/*   altmatch = conn->altsubject_match; */
/*   suffix_match = conn->suffix_match; */

/*   if (!preverify_ok && !conn->ca_cert_verify) */
/*     preverify_ok = 1; */
/*   if (!preverify_ok && depth > 0 && conn->server_cert_only) */
/*     preverify_ok = 1; */
/*   if (!preverify_ok && (conn->flags & TLS_CONN_DISABLE_TIME_CHECKS) && */
/*       (err == X509_V_ERR_CERT_HAS_EXPIRED || */
/*        err == X509_V_ERR_CERT_NOT_YET_VALID)) { */
/*     wpa_printf(MSG_DEBUG, "OpenSSL: Ignore certificate validity " */
/* 	       "time mismatch"); */
/*     preverify_ok = 1; */
/*   } */

/*   err_str = X509_verify_cert_error_string(err); */

/* #ifdef CONFIG_SHA256 */
/*   if (preverify_ok && depth == 0 && conn->server_cert_only) { */
/*     struct wpabuf *cert; */
/*     cert = get_x509_cert(err_cert); */
/*     if (!cert) { */
/*       wpa_printf(MSG_DEBUG, "OpenSSL: Could not fetch " */
/* 		 "server certificate data"); */
/*       preverify_ok = 0; */
/*     } else { */
/*       u8 hash[32]; */
/*       const u8 *addr[1]; */
/*       size_t len[1]; */
/*       addr[0] = wpabuf_head(cert); */
/*       len[0] = wpabuf_len(cert); */
/*       if (sha256_vector(1, addr, len, hash) < 0 || */
/* 	  os_memcmp(conn->srv_cert_hash, hash, 32) != 0) { */
/* 	err_str = "Server certificate mismatch"; */
/* 	err = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN; */
/* 	preverify_ok = 0; */
/*       } */
/*       wpabuf_free(cert); */
/*     } */
/*   } */
/* #endif /\* CONFIG_SHA256 *\/ */

/*   if (!preverify_ok) { */
/*     wpa_printf(MSG_WARNING, "TLS: Certificate verification failed," */
/* 	       " error %d (%s) depth %d for '%s'", err, err_str, */
/* 	       depth, buf); */
/*     openssl_tls_fail_event(conn, err_cert, err, depth, buf, */
/* 			   err_str, TLS_FAIL_UNSPECIFIED); */
/*     return preverify_ok; */
/*   } */

/*   wpa_printf(MSG_DEBUG, "TLS: tls_verify_cb - preverify_ok=%d " */
/* 	     "err=%d (%s) ca_cert_verify=%d depth=%d buf='%s'", */
/* 	     preverify_ok, err, err_str, */
/* 	     conn->ca_cert_verify, depth, buf); */
/*   if (depth == 0 && match && os_strstr(buf, match) == NULL) { */
/*     wpa_printf(MSG_WARNING, "TLS: Subject '%s' did not " */
/* 	       "match with '%s'", buf, match); */
/*     preverify_ok = 0; */
/*     openssl_tls_fail_event(conn, err_cert, err, depth, buf, */
/* 			   "Subject mismatch", */
/* 			   TLS_FAIL_SUBJECT_MISMATCH); */
/*   } else if (depth == 0 && altmatch && */
/* 	     !tls_match_altsubject(err_cert, altmatch)) { */
/*     wpa_printf(MSG_WARNING, "TLS: altSubjectName match " */
/* 	       "'%s' not found", altmatch); */
/*     preverify_ok = 0; */
/*     openssl_tls_fail_event(conn, err_cert, err, depth, buf, */
/* 			   "AltSubject mismatch", */
/* 			   TLS_FAIL_ALTSUBJECT_MISMATCH); */
/*   } else if (depth == 0 && suffix_match && */
/* 	     !tls_match_suffix(err_cert, suffix_match)) { */
/*     wpa_printf(MSG_WARNING, "TLS: Domain suffix match '%s' not found", */
/* 	       suffix_match); */
/*     preverify_ok = 0; */
/*     openssl_tls_fail_event(conn, err_cert, err, depth, buf, */
/* 			   "Domain suffix mismatch", */
/* 			   TLS_FAIL_DOMAIN_SUFFIX_MISMATCH); */
/*   } else */
/*     openssl_tls_cert_event(conn, err_cert, depth, buf); */

/*   if (conn->cert_probe && preverify_ok && depth == 0) { */
/*     wpa_printf(MSG_DEBUG, "OpenSSL: Reject server certificate " */
/* 	       "on probe-only run"); */
/*     preverify_ok = 0; */
/*     openssl_tls_fail_event(conn, err_cert, err, depth, buf, */
/* 			   "Server certificate chain probe", */
/* 			   TLS_FAIL_SERVER_CHAIN_PROBE); */
/*   } */

/*   if (preverify_ok && context->event_cb != NULL) */
/*     context->event_cb(context->cb_ctx, */
/* 		      TLS_CERT_CHAIN_SUCCESS, NULL); */

  wpa_printf(MSG_DEBUG, "CyaSSL: verification fail");
  return preverify_ok;
}


static int tls_connection_ca_cert(void *_ssl_ctx, struct tls_connection *conn,
				  const char *ca_cert, const u8 *ca_cert_blob,
				  size_t ca_cert_blob_len, const char *ca_path)
{
  SSL_CTX *ssl_ctx = _ssl_ctx;

  /*
   * Remove previously configured trusted CA certificates before adding
   * new ones.
   */
  CyaSSL_X509_STORE_free(conn->cert_store);
  conn->cert_store = CyaSSL_X509_STORE_new();
  if (conn->cert_store == NULL) {
    wpa_printf(MSG_DEBUG, "CyaSSL: %s - failed to allocate new "
	       "certificate store", __func__);
    return -1;
  }

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
    X509 *cert = CyaSSL_X509_d2i(NULL, ca_cert_blob, ca_cert_blob_len);
    if (cert == NULL) {
      tls_show_errors(MSG_WARNING, __func__,
		      "Failed to parse ca_cert_blob");
      return -1;
    }

    if (!CyaSSL_X509_STORE_add_cert(conn->cert_store, cert)) {
      tls_show_errors(MSG_WARNING, __func__,
		      "Failed to add ca_cert_blob to "
		      "certificate store");
      X509_free(cert);
      return -1;
    }

    X509_free(cert);
    wpa_printf(MSG_DEBUG, "CyaSSL: %s - added ca_cert_blob "
	       "to certificate store", __func__);
    return 0;
  }

  if (ca_cert || ca_path) {
#ifndef OPENSSL_NO_STDIO
    if (CyaSSL_CTX_load_verify_locations(ssl_ctx, ca_cert, ca_path)
	!= SSL_SUCCESS) {
      tls_show_errors(MSG_WARNING, __func__,
		      "Failed to load root certificates");
      return -1;
    } else {
      wpa_printf(MSG_DEBUG, "TLS: Trusted root "
		 "certificate(s) loaded");
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
    if (SSL_CTX_load_verify_locations(ssl_ctx, ca_cert, NULL) != 1)
      {
	tls_show_errors(MSG_WARNING, __func__,
			"Failed to load root certificates");
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
#ifdef HAVE_CRL
  if (check_crl) {
    int flags;
    int i;
    X509_STORE *cs = NULL;

    for (i = 0; i < MAX_CONN; i++) {
      if (ssl_conn[i] && ssl_conn[i]->ssl_ctx == ssl_ctx) {
	cs = ssl_conn[i]->cert_store;
	break;
      }
    }

    if (cs == NULL) {
      tls_show_errors(MSG_INFO, __func__, "Failed to get "
		      "certificate store when enabling "
		      "check_crl");
      return -1;
    }
    flags = X509_V_FLAG_CRL_CHECK;
    if (check_crl == 2)
      flags |= X509_V_FLAG_CRL_CHECK_ALL;
    X509_STORE_set_flags(cs, flags);
  }
#endif
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
      tls_show_errors(MSG_DEBUG, __func__,
		      "SSL_use_certificate_ASN1 failed");
    }
  }

  if (client_cert == NULL)
    return -1;

#ifndef OPENSSL_NO_STDIO
  if (CyaSSL_use_certificate_file(conn->ssl,
				  client_cert,
				  SSL_FILETYPE_ASN1) == 1) {
    wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_file (DER)"
	       " --> OK");
    return 0;
  }

  if (CyaSSL_use_certificate_file(conn->ssl,
				  client_cert,
				  SSL_FILETYPE_PEM) == 1) {
    ERR_clear_error();
    wpa_printf(MSG_DEBUG, "CyaSSL: SSL_use_certificate_file (PEM)"
	       " --> OK");
    return 0;
  }

  tls_show_errors(MSG_DEBUG, __func__,
		  "SSL_use_certificate_file failed");
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

  if (SSL_CTX_use_certificate_file(ssl_ctx, client_cert,
				   SSL_FILETYPE_ASN1) != 1 &&
      SSL_CTX_use_certificate_chain_file(ssl_ctx, client_cert) != 1 &&
      SSL_CTX_use_certificate_file(ssl_ctx, client_cert,
				   SSL_FILETYPE_PEM) != 1) {
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to load client certificate");
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
    tls_show_errors(MSG_DEBUG, __func__,
		    "Failed to parse PKCS12 file");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to use PKCS#12 file");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to use PKCS#12 blob");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to load private key");
    os_free(passwd);
    return -1;
  }
  ERR_clear_error();
  SSL_CTX_set_default_passwd_cb(ssl_ctx, NULL);
  os_free(passwd);

  if (!CyaSSL_CTX_check_private_key(conn->ssl_ctx)) {
    tls_show_errors(MSG_INFO, __func__, "Private key failed "
		    "verification");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Failed to load private key");
    os_free(passwd);
    ERR_clear_error();
    return -1;
  }
  os_free(passwd);
  ERR_clear_error();
  SSL_CTX_set_default_passwd_cb(ssl_ctx, NULL);

  if (!SSL_CTX_check_private_key(ssl_ctx)) {
    tls_show_errors(MSG_INFO, __func__,
		    "Private key failed verification");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Handshake failed - BIO_write");
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
      tls_show_errors(MSG_INFO, __func__, "SSL_connect");
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
      tls_show_errors(MSG_INFO, __func__,
		      "Failed to read possible "
		      "Application Data");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Encryption failed - SSL_write");
    return NULL;
  }

  /* Read encrypted data to be sent to the server */
  if (!conn->ssl_out) {
    tls_show_errors(MSG_INFO, __func__, "No ssl_out");
    return NULL;
  }

  buf = wpabuf_dup(conn->ssl_out);
  if (buf == NULL) {
    tls_show_errors(MSG_INFO, __func__, "Out of memory");
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
    tls_show_errors(MSG_INFO, __func__, "Out of memory");
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
    tls_show_errors(MSG_INFO, __func__, "out of memory");
    return NULL;
  }

  res = CyaSSL_read(conn->ssl, wpabuf_mhead(buf), wpabuf_size(buf));
  if (res < 0) {
    tls_show_errors(MSG_INFO, __func__,
		    "Decryption failed - SSL_read");
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
    tls_show_errors(MSG_INFO, __func__,
		    "Cipher suite configuration failed");
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
  unsigned long err;

  if (conn == NULL)
    return -1;

  while ((err = ERR_get_error())) {
    wpa_printf(MSG_INFO, "%s: Clearing pending SSL error: %s",
	       __func__, ERR_error_string(err, NULL));
  }

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
