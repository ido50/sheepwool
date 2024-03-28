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

#include <errno.h>
#include <microhttpd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "sheepwool.h"

enum MHD_Result serve_html(struct server_info *srv_info,
                           struct MHD_Connection *conn, struct request *req) {
	if (srv_info->html_handler == NULL) {
		// We do not have an HTML handler, so we're just serving this as any other
		// file
		return serve_file(srv_info, conn, req);
	}

	int rc = MHD_NO;
	FILE *file;

	file = fopen(req->res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		goto cleanup;
	}

	req->input = fileno(file);

	rc = serve_psgi(srv_info, conn, req);

cleanup:
	if (file)
		fclose(file);

	return rc;
}
