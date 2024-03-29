/*	$Id$ */
/*
 * Copyright (c) 2024 Ido Perlmuter <sheepwool@ido50.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _XOPEN_SOURCE_EXTENDED
#define _LARGEFILE64_SOURCE
#define _ISOC99_SOURCE
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <uthash.h>

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "sheepwool.h"

EXTERN_C void xs_init (pTHX);
static PerlInterpreter *my_perl;

int start_perl(int argc, char **argv, char **env) {
	PERL_SYS_INIT3(&argc, &argv, &env);
	char *embedding[] = { "", "persistent.pl", NULL };

	my_perl = perl_alloc();
	if(my_perl == NULL) {
		fprintf(stderr, "Failed allocating memory for Perl: %s\n", strerror(errno));
		return 1;
	}

	perl_construct(my_perl);

	PL_origalen = 1; // Don't let $0 assignment update the proctitle or embedding[0]

	int rc = perl_parse(my_perl, xs_init, 2, embedding, NULL);

	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	if (rc)
		return rc;

	return perl_run(my_perl);
}

void destroy_perl() {
	if (my_perl != NULL) {
		PL_perl_destruct_level = 0;
		perl_destruct(my_perl);
		perl_free(my_perl);
	}

	PERL_SYS_TERM();

}

static void psgi_header_name(char *dest, const char *orig, int len) {
	strcpy(dest, "HTTP_");
	for (int i = 5; i <= len-1; i++) {
		if (orig[i-5] == '-')
			dest[i] = '_';
		else
			dest[i] = toupper(orig[i-5]);
	}
	dest[len] = '\0';
}

static HV* create_psgi_env(struct evhttp_request *conn, struct request *req) {
	HV *env = newHV();
	hv_stores(env, "REQUEST_METHOD", newSVpv(req->method_str, 0));
	hv_stores(env, "SCRIPT_NAME", newSVpv("", 0));
	hv_stores(env, "PATH_INFO", newSVpv(req->path, 0));
	hv_stores(env, "REQUEST_URI", newSVpv(evhttp_request_get_uri(conn), 0));
	hv_stores(env, "QUERY_STRING", newSVpv(evhttp_uri_get_query(req->uri), 0));
	hv_stores(env, "SERVER_PROTOCOL", newSVpv("1.1", 0));

	bool is_https = false;

	struct header *current_header, *tmp;
	HASH_ITER(hh, req->headers, current_header, tmp) {
		int len = 5 + strlen(current_header->key);
		char header[len+1];
		psgi_header_name(header, current_header->key, len);

		const char *val = current_header->value;

		hv_store(env, header, len, newSVpv(val, 0), 0);

		if (strcmp(header, "HTTP_X_FORWARDED_PROTO") == 0)
			if (strcmp(val, "https") == 0)
				is_https = true;
			else if (strcmp(header, "HTTP_CONTENT_TYPE") == 0)
				hv_stores(env, "CONTENT_TYPE", newSVpv(val, 0));
			else if (strcmp(header, "HTTP_CONTENT_LENGTH") == 0)
				hv_stores(env, "CONTENT_LENGTH", newSVpv(val, 0));
	}

	AV *version = newAV();
	av_push(version, newSViv(1));
	av_push(version, newSViv(1));
	hv_stores(env, "psgi.version", newRV_noinc((SV *) version));

	hv_stores(env, "psgi.url_scheme", is_https ? newSVpv("https", 5) : newSVpv("http", 4));
	hv_stores(env, "psgi.run_once", newSViv(0));
	hv_stores(env, "psgi.streaming", newSViv(0));
	hv_stores(env, "psgi.nonblocking", newSViv(1));

	if (req->input)
		hv_stores(env, "psgi.input", newSViv(req->input));
	hv_stores(env, "psgi.errors", newSViv(2));

	return env;
}

static SV* eval_psgi(
	struct evhttp_request *conn, struct request *req, struct resource *res) {
	dSP;
	int count;
	SV *res_rv = NULL;
	HV *env = NULL;

	const char *script = req->delegate ? req->delegate : res->fullpath;

	DEBUG_PRINT("Evaluating PSGI script [%s]\n", script);

	ENTER;
	SAVETMPS;

	env = create_psgi_env(conn, req);
	if (env == NULL)
		goto cleanup;

	PUSHMARK(SP);
	EXTEND(SP, 2);
	PUSHs(sv_2mortal(newSVpv(script, 0)));
	PUSHs(sv_2mortal(newRV_inc((SV*)env)));
	PUTBACK;

	count = call_pv("Embed::Persistent::run_psgi", G_SCALAR|G_EVAL);

	SPAGAIN;

	SV *err = ERRSV;
	if (SvTRUE(err)) {
		fprintf(stderr, "PSGI app %s failed: %s", script, SvPV_nolen(err));
		POPs;
		goto cleanup;
	}

	if (count != 1) {
		fprintf(stderr, "run_psgi returned %d instead of 1 result value\n", count);
		return NULL;
	}

	res_rv = POPs;
	SvREFCNT_inc(res_rv);

cleanup:
	PUTBACK;
	FREETMPS;
	LEAVE;

	return res_rv;
}

static struct evbuffer *parse_output_body(AV *res_av, size_t *size) {
	SV *res_body = *(av_fetch(res_av, 2, 0));
	AV *res_body_av = (AV *) SvRV(res_body);

	struct evbuffer *buffer = evbuffer_new();

	for (I32 i = 0; i <= av_len(res_body_av); i++) {
		SV *b = (SV *) *(av_fetch(res_body_av, i, 0));
		if (SvOK(b)) {
			STRLEN len;
			char *line = SvPV(b, len);
			evbuffer_add(buffer, line, len);
			*size += len;
		}
	}

	return buffer;
}


struct response *serve_psgi(
	struct server_info *srv_info,
	struct evhttp_request *conn,
	struct request *req,
	struct resource *res) {
	PERL_SET_CONTEXT(my_perl);

	SV *res_rv = NULL;

	res_rv = eval_psgi(conn, req, res);
	if (res_rv == NULL)
		goto cleanup;

	AV *res_av = (AV *)SvRV(res_rv);

	struct response *resp = malloc(sizeof *resp);
	if (resp == NULL) {
		fprintf(stderr, "Failed allocating for response: %s\n", strerror(errno));
		goto cleanup;
	}

	resp->status = 0;
	resp->etag = NULL;
	resp->content_length = 0;
	resp->content_type = NULL;
	resp->content_encoding = NULL;
	resp->content = NULL;
	resp->extra_headers = NULL;

	// Process response status
	SV *status = (SV *) *(av_fetch(res_av, 0, 0));
	resp->status = SvIV(status);

	// Process response headers
	SV *res_headers = *(av_fetch(res_av, 1, 0));
	AV *res_headers_av = (AV *) SvRV(res_headers);

	while (av_len(res_headers_av) > -1) {
		SV *key_sv = av_shift(res_headers_av);
		SV *val_sv = av_shift(res_headers_av);

		if (key_sv == NULL || val_sv == NULL)
			break;

		struct header *h = malloc(sizeof *h);
		if (h == NULL) {
			fprintf(stderr, "Failed allocating for output header: %s\n", strerror(errno));
			resp = NULL;
			goto cleanup;
		}

		h->key = SvPV_nolen(key_sv);

		if (strcmp(h->key, "Content-Type") == 0) {
			resp->content_type = SvPV_nolen(val_sv);
		} else {
			h->value = SvPV_nolen(val_sv);
			HASH_ADD_STR(resp->extra_headers, key, h);
		}

		SvREFCNT_dec(key_sv);
		SvREFCNT_dec(val_sv);
	}

	// Process response body
	resp->content = parse_output_body(res_av, &resp->content_length);

cleanup:
	if (res_rv == NULL)
		return NULL;

	SvREFCNT_dec(res_rv);

	return resp;
}
