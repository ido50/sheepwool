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
#include <fcntl.h>
#include <microhttpd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <uthash.h>

#include "sheepwool.h"

enum MHD_Result serve_html(struct server_info *srv_info,
                           struct MHD_Connection *conn, struct request *req) {
	if (srv_info->html_handler == NULL)
		// We do not have an HTML handler, so we're just serving this as any other
		// file
		return serve_file(srv_info, conn, req);

	int rc = MHD_NO;
	int fd = -1;

	fd = open(req->res->fullpath, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return rc;
	}

	char content_length[21];
	struct param *header = malloc(sizeof *header);
	header->name = "Content-Length";
	snprintf(content_length, 21, "%ld", req->res->size);
	header->value = content_length;

	HASH_ADD_STR(req->headers, name, header);

	req->input = fd;
	req->delegate = srv_info->html_handler;

	DEBUG_PRINT("Delegating to %s\n", srv_info->html_handler);

	rc = serve_psgi(srv_info, conn, req);

	close(fd);

	return rc;
}
