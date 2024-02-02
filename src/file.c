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
#include <magic.h>
#include <microhttpd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "sheepwool.h"

static uLong calculate_etag(struct request *req) {
	uLong crc = crc32(0L, Z_NULL, 0); // Initialize the CRC

	if (req->resp->content_encoding != NULL) {
		crc = crc32(crc, (const Bytef *)req->resp->content, req->resp->size);
		return crc;
	}

	unsigned char buffer[1024];
	size_t bytes_read;

	FILE *file = fopen(req->res->fullpath, "rb");
	if (file == NULL) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return 0;
	}

	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		crc = crc32(crc, buffer, bytes_read);
	}

	if (ferror(file)) {
		fprintf(stderr, "Failed reading file %s: %s\n", req->res->fullpath, strerror(errno));
		fclose(file);
		return 0;
	}

	fclose(file);

	return crc;
}

enum MHD_Result serve_file(struct server_info *srv_info,
                           struct MHD_Connection *conn,
                           struct request *req) {
	req->resp = malloc(sizeof *req->resp);
	if (req->resp == NULL) {
		fprintf(stderr, "Failed allocating for resource: %s\n", strerror(errno));
		return MHD_NO;
	}

	req->resp->status = MHD_HTTP_OK;
	req->resp->size = req->res->size;
	req->resp->etag = NULL;
	req->resp->location = NULL;
	req->resp->content = NULL;
	req->resp->content_encoding = "none";
	req->resp->backend = NULL;

	req->resp->content_type =
		has_suffix(req->res->fullpath, ".css") ? strdup("text/css") :
		strdup(magic_file(srv_info->magic_db, req->res->fullpath));
	if (req->resp->content_type == NULL)
		req->resp->content_type = strdup("text/plain");

	// Compress the file if it's compressible and client supports it
	if (!(is_compressible(req->resp->content_type) && compress_file(srv_info, req))) {
		FILE *file = fopen(req->res->fullpath, "rb");
		if (!file) {
			fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
			return MHD_NO;
		}

		req->resp->content = malloc(req->res->size + 1);
		if (!req->resp->content) {
			fprintf(stderr, "Failed allocating memory for file: %s\n", strerror(errno));
			fclose(file);
			return MHD_NO;
		}

		size_t bytesRead = fread(req->resp->content, 1, req->res->size, file);
		if (bytesRead < req->res->size) {
			fprintf(stderr, "Failed reading file: %s\n", strerror(errno));
			fclose(file);
			return MHD_NO;
		}

		req->resp->content[bytesRead] = '\0';
		req->resp->size = req->res->size;
	}

	req->resp->backend = MHD_create_response_from_buffer(
		req->resp->size, req->resp->content, MHD_RESPMEM_PERSISTENT);

	if (req->resp->backend == NULL) {
		fprintf(stderr, "Failed creating response from fd: %s\n", strerror(errno));
		return MHD_NO;
	}

	// Calcualte the file's ETag
	uLong etag = calculate_etag(req);
	if (etag > 0) {
		req->resp->etag = malloc(11);
		sprintf((char *)req->resp->etag, "\"%08lx\"", etag);
		req->resp->etag[10] = '\0';
		DEBUG_PRINT("Calculated etag: %s\n", req->resp->etag);
	}

	save_response_to_cache(srv_info, req);

	if (req->resp->content_type != NULL)
		MHD_add_response_header(req->resp->backend, "Content-Type", (const char *)req->resp->content_type);

	if (req->resp->content_encoding != NULL)
		MHD_add_response_header(req->resp->backend, "Content-Encoding", (const char *)req->resp->content_encoding);

	if (req->resp->etag != NULL)
		MHD_add_response_header(req->resp->backend, "ETag", (const char *)req->resp->etag);

	return MHD_queue_response(conn, req->resp->status, req->resp->backend);
}
