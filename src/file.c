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
#include <event2/buffer.h>
#include <event2/http.h>
#include <fcntl.h>
#include <magic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "sheepwool.h"

static uLong calculate_etag(struct resource *res, struct response *resp) {
	uLong crc = crc32(0L, Z_NULL, 0); // Initialize the CRC

	if (resp->content_encoding != NULL) {
		crc = crc32(crc, (const Bytef *)resp->content, resp->content_length);
		return crc;
	}

	unsigned char buffer[1024];
	size_t bytes_read;

	FILE *file = fopen(res->fullpath, "rb");
	if (file == NULL) {
		fprintf(stderr, "Failed opening file %s: %s\n", res->fullpath, strerror(errno));
		return 0;
	}

	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		crc = crc32(crc, buffer, bytes_read);
	}

	if (ferror(file)) {
		fprintf(stderr, "Failed reading file %s: %s\n", res->fullpath, strerror(errno));
		fclose(file);
		return 0;
	}

	fclose(file);

	return crc;
}

struct response *serve_file(struct server_info *srv_info,
                            struct evhttp_request *conn,
                            struct request *req,
                            struct resource *res) {
	struct response *resp = malloc(sizeof *resp);
	if (resp == NULL) {
		fprintf(stderr, "Failed allocating for resource: %s\n", strerror(errno));
		return NULL;
	}

	resp->status = HTTP_OK;
	resp->content_length = res->size;
	resp->etag[0] = '\0';
	resp->content = NULL;
	resp->content_encoding = "none";

	resp->content_type =
		has_suffix(res->fullpath, ".css") ? "text/css" :
		magic_file(srv_info->magic_db, res->fullpath);
	if (resp->content_type == NULL)
		resp->content_type = "text/plain";

	resp->content = evbuffer_new();
	if (resp->content == NULL) {
		fprintf(stderr, "Failed allocating for response buffer: %s\n", strerror(errno));
		evhttp_send_error(conn, HTTP_INTERNAL, 0);
		return NULL;
	}

	if (req->method == EVHTTP_REQ_OPTIONS) {
		evhttp_add_header(evhttp_request_get_output_headers(conn), "Allow", "GET, HEAD, OPTIONS");
		resp->content_length = 0;
	}

	// Compress the file if it's compressible and client supports it
	if (is_compressible(resp->content_type)) {
		evhttp_add_header(evhttp_request_get_output_headers(conn), "Vary", "Accept-Encoding");

		if (resp->content_length == 0)
			return resp;

		unsigned char *compressed_content = compress_file(srv_info, req, res, resp);
		if (compressed_content) {
			DEBUG_PRINT(
				"Compressed %s with %s to %lo bytes\n",
				res->fullpath, resp->content_encoding, resp->content_length);

			// Calcualte the file's ETag
			uLong etag = calculate_etag(res, resp);
			if (etag > 0) {
				sprintf(resp->etag, "\"%08lx\"", etag);
				resp->etag[10] = '\0';
				DEBUG_PRINT("Calculated etag: %s\n", resp->etag);
			}

			char *compressed_path = save_response_to_cache(req, res, resp, compressed_content);
			if (compressed_path) {
				int fd = open(compressed_path, O_RDONLY);
				if (fd == -1) {
					fprintf(stderr, "Failed opening compressed representation %s: %s\n", compressed_path, strerror(errno));
					return NULL;
				}

				evbuffer_add_file(resp->content, fd, 0, resp->content_length);
				close(fd);
				return resp;
			}
		}
	}

	int fd = open(res->fullpath, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed opening file %s: %s\n", res->fullpath, strerror(errno));
		return NULL;
	}

	evbuffer_add_file(resp->content, fd, 0, resp->content_length);

	close(fd);

	return resp;
}
