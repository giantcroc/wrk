// Copyright (C) 2013 - Will Glozer.  All rights reserved.

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pool.h>
#include <zlib.h>

#include "ssl.h"

// static int zlib_decompress(SSL *s, CRYPTO_BUFFER **out, size_t uncompressed_len,
//                                              const uint8_t *in, size_t in_len)
// {
//     size_t outlen = uncompressed_len;
//     uint8_t * outbuf =malloc(outlen);

//     // printf("%d %d\n",uncompressed_len,in_len);
//     if (uncompress(outbuf, &outlen, in, in_len) != Z_OK)
//         return 0;

//     if (outlen != uncompressed_len)
//         return 0;
//     else{
//         *out=CRYPTO_BUFFER_new(outbuf,outlen,NULL);
//         free(outbuf);
//     }

//     return 1;
// }

static int zlib_decompress(SSL *s, CRYPTO_BUFFER **out, size_t uncompressed_len,
                                             const uint8_t *in, size_t in_len)
{
    size_t outlen = uncompressed_len;
    uint8_t * outbuf =malloc(outlen);

    z_stream d_stream; /* decompression stream */
    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = NULL;
    d_stream.next_in = in;
    d_stream.avail_in = in_len;
    d_stream.next_out = outbuf;
    d_stream.avail_out=outlen;


	int err = -1;
	err = inflateInit2(&d_stream, MAX_WBITS + 16);

	if (err == Z_OK)
	{
		err = inflate(&d_stream, Z_FINISH);
		if (err != Z_STREAM_END)
		{
			(void)inflateEnd(&d_stream);
			printf("decompression failed, inflate return: \n");

			return 0;
		}
	}
	else
	{
		inflateEnd(&d_stream);
		printf("decompression initialization failed, quit!\n");
		return 0;
    }

    (void)inflateEnd(&d_stream);
	// printf("decompress succed, before decompress size is %d, after decompress size is %d\n", d_stream.total_in, d_stream.avail_out);
    outlen=d_stream.total_out;

    if (outlen != uncompressed_len)
        return 0;
    else{
        *out=CRYPTO_BUFFER_new(outbuf,outlen,NULL);
        free(outbuf);
    }

    return 1;
}

SSL_CTX *ssl_init() {
    SSL_CTX *ctx = NULL;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    if ((ctx = SSL_CTX_new(SSLv23_client_method()))) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_verify_depth(ctx, 0);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

        SSL_CTX_add_cert_compression_alg(ctx, 1,
                                        NULL, zlib_decompress);
    }

    return ctx;
}

status ssl_connect(connection *c, char *host) {
    int r;
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, host);
    if ((r = SSL_connect(c->ssl)) != 1) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    return OK;
}

status ssl_close(connection *c) {
    SSL_shutdown(c->ssl);
    SSL_clear(c->ssl);
    return OK;
}

status ssl_read(connection *c, size_t *n) {
    int r;
    if ((r = SSL_read(c->ssl, c->buf, sizeof(c->buf))) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

status ssl_write(connection *c, char *buf, size_t len, size_t *n) {
    int r;
    if ((r = SSL_write(c->ssl, buf, len)) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

size_t ssl_readable(connection *c) {
    return SSL_pending(c->ssl);
}
