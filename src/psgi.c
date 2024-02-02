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
#include <curl/curl.h>
#include <errno.h>
#include <microhttpd.h>
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

static HV* create_psgi_env(struct request *req) {
	char *path;
	char *qs;
	CURLUcode rc = curl_url_get(req->url, CURLUPART_PATH, &path, CURLU_URLDECODE);
	if (rc != CURLUE_OK) {
		fprintf(stderr, "Failed getting request path: %s\n", curl_url_strerror(rc));
		return NULL;
	}

	rc = curl_url_get(req->url, CURLUPART_QUERY, &qs, CURLU_URLDECODE);
	if (rc != CURLUE_OK && rc != CURLUE_NO_QUERY) {
		fprintf(stderr, "Failed getting request query string: %s\n", curl_url_strerror(rc));
		return NULL;
	}

	DEBUG_PRINT("Query string is %s\n", qs);

	HV *env = newHV();
	hv_stores(env, "REQUEST_METHOD", newSVpv(req->method, 0));
	hv_stores(env, "SCRIPT_NAME", newSVpv("", 0));
	hv_stores(env, "PATH_INFO", newSVpv(path, 0));
	hv_stores(env, "REQUEST_URI", newSVpv(req->raw_path, 0));
	hv_stores(env, "QUERY_STRING", newSVpv(qs, 0));
	hv_stores(env, "SERVER_PROTOCOL", newSVpv(req->version, 0));

	curl_free(path);
	curl_free(qs);

	bool is_https = false;

	struct param *current_header, *tmp;
	HASH_ITER(hh, req->headers, current_header, tmp) {
		int len = 5 + strlen(current_header->name);
		char header[len+1];
		psgi_header_name(header, current_header->name, len);

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

	return env;
}

static SV* eval_psgi(struct request *req) {
	dSP;
	int count;
	SV *res_rv = NULL;
	HV *env = NULL;

	DEBUG_PRINT("Evaluating PSGI script [%s]\n", req->res->fullpath);

	ENTER;
	SAVETMPS;

	env = create_psgi_env(req);
	if (env == NULL)
		goto cleanup;

	PUSHMARK(SP);
	EXTEND(SP, 2);
	PUSHs(sv_2mortal(newSVpv(req->res->fullpath, 0)));
	PUSHs(sv_2mortal(newRV_inc((SV*)env)));
	PUTBACK;

	count = call_pv("Embed::Persistent::run_psgi", G_SCALAR|G_EVAL);

	SPAGAIN;

	SV *err = ERRSV;
	if (SvTRUE(err)) {
		fprintf(stderr, "PSGI app %s failed: %s", req->res->fullpath, SvPV_nolen(err));
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

static unsigned char* parse_output_body(AV *res_av, size_t *size) {
	SV *res_body = *(av_fetch(res_av, 2, 0));
	AV *res_body_av = (AV *) SvRV(res_body);

	unsigned char *buffer = NULL;
	unsigned char *p = NULL;

	*size = 0;

	for (I32 i = 0; i <= av_len(res_body_av); i++) {
		SV *b = (SV *) *(av_fetch(res_body_av, i, 0));
		if (SvOK(b)) {
			STRLEN len;
			char *line = SvPV(b, len);
			*size += (size_t) len;

			if (buffer == NULL) {
				buffer = malloc(len+1);
				p = buffer;
			} else {
				buffer = realloc(buffer, len+1);
			}

			if (buffer == NULL) {
				fprintf(stderr, "Failed allocating memory for PSGI body: %s\n", strerror(errno));
				return NULL;
			}

			p = stpcpy(p, line);
		}
	}

	return buffer;
}

enum MHD_Result serve_psgi(struct MHD_Connection *conn, struct request *req) {
	PERL_SET_CONTEXT(my_perl);

	enum MHD_Result res = MHD_NO;
	SV *res_rv = NULL;

	res_rv = eval_psgi(req);
	if (res_rv == NULL)
		goto cleanup;

	AV *res_av = (AV *)SvRV(res_rv);

	req->resp = malloc(sizeof *req->resp);
	req->resp->status = 0;
	req->resp->size = 0;
	req->resp->etag = NULL;
	req->resp->location = NULL;
	req->resp->content_type = NULL;
	req->resp->content = NULL;
	req->resp->backend = NULL;
	req->resp->content_encoding = "none";

	req->resp->content = parse_output_body(res_av, &req->resp->size);
	if (req->resp->content == NULL)
		goto cleanup;

	// Process response status
	SV *status = (SV *) *(av_fetch(res_av, 0, 0));

	// Create the MHD response object from the body buffer
	req->resp->backend = MHD_create_response_from_buffer(req->resp->size, req->resp->content, MHD_RESPMEM_MUST_COPY);
	if (req->resp->backend == NULL) {
		fprintf(stderr, "Failed creating response from buffer: %s\n", strerror(errno));
		goto cleanup;
	}

	// Process response header
	SV *res_headers = *(av_fetch(res_av, 1, 0));
	AV *res_headers_av = (AV *) SvRV(res_headers);

	while (av_len(res_headers_av) > -1) {
		SV *key_sv = av_shift(res_headers_av);
		SV *val_sv = av_shift(res_headers_av);

		if (key_sv == NULL || val_sv == NULL)
			break;

		MHD_add_response_header(req->resp->backend, SvPV_nolen(key_sv), SvPV_nolen(val_sv));

		SvREFCNT_dec(key_sv);
		SvREFCNT_dec(val_sv);
	}

	res = MHD_queue_response(conn, SvIV(status), req->resp->backend);

cleanup:
	if (res_rv != NULL)
		SvREFCNT_dec(res_rv);

	return res;
}
