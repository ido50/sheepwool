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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sheepwool.h"

static char *add_extension(const char *path, const char *ext) {
	size_t path_len = strlen(path);
	size_t ext_len = strlen(ext);

	size_t new_path_len = path_len + ext_len + 2;

	char *new_path = calloc(1, new_path_len);
	if (!new_path) {
		fprintf(stderr, "Failed allocating memory for new path: %s\n", strerror(errno));
		return NULL;
	}

	strncpy(new_path, path, path_len);

	if (ext[0] != '.') {
		new_path[path_len] = '.';
		new_path[path_len + 1] = '\0';
	}

	strncat(new_path, ext, ext_len);

	return new_path;
}

static char *can_load_file(
	const char *path,
	const char *extension,
	struct timespec orig_mtime,
	off_t *size) {
	char *fullpath = add_extension(path, extension);

	struct stat fstat;
	if (lstat(fullpath, &fstat) != 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed stating file %s: %s\n", fullpath, strerror(errno));
		return NULL;
	}

	if (!S_ISREG(fstat.st_mode)) {
		return NULL;
	}

	if (fstat.st_mtim.tv_sec < orig_mtime.tv_sec ||
	    (fstat.st_mtim.tv_sec == orig_mtime.tv_sec &&
	     fstat.st_mtim.tv_nsec < orig_mtime.tv_nsec)) {
		// File is older than original, do not return
		return NULL;
	}

	*size = fstat.st_size;

	return fullpath;
}

static char *load_file(
	const char *path,
	const char *extension,
	struct timespec orig_mtime,
	off_t *size) {
	char *buffer = NULL;
	FILE *file = NULL;
	char *fullpath = add_extension(path, extension);

	struct stat fstat;
	if (lstat(fullpath, &fstat) != 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed stating file %s: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	if (!S_ISREG(fstat.st_mode)) {
		goto cleanup;
	}

	if (fstat.st_mtim.tv_sec < orig_mtime.tv_sec ||
	    (fstat.st_mtim.tv_sec == orig_mtime.tv_sec &&
	     fstat.st_mtim.tv_nsec < orig_mtime.tv_nsec)) {
		// File is older than original, do not return
		*size = -1;
		goto cleanup;
	}

	if (size != NULL)
		*size = fstat.st_size;

	file = fopen(fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	buffer = malloc(fstat.st_size + 1);
	if (!buffer) {
		fprintf(stderr, "Failed allocating for file %s: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	size_t bytes_read = fread(buffer, 1, fstat.st_size, file);
	if (bytes_read < fstat.st_size) {
		free(buffer);
		goto cleanup;
	}

	buffer[fstat.st_size] = '\0';

cleanup:
	if (file)
		fclose(file);
	if (fullpath)
		free(fullpath);

	return buffer;
}

static char *save_file(const char *path,
                       const char *extension,
                       unsigned const char *buffer,
                       off_t len) {
	FILE *file;
	char *fullpath = add_extension(path, extension);

	file = fopen(fullpath, "w");
	if (!file) {
		fprintf(stderr, "Failed opening file %s for writing: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	if (len == 0)
		len = strlen((char*)buffer);

	// Write the buffer to the file.
	size_t written = fwrite(buffer, 1, len, file);
	if (written < len) {
		fprintf(stderr, "Failed writing to file %s: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

cleanup:
	if (file)
		fclose(file);

	return fullpath;
}

struct response *try_serving_from_cache(
	struct server_info *srv_info,
	struct evhttp_request *conn,
	struct request *req,
	struct resource *res) {
	DEBUG_PRINT("Trying to serve %s from cache\n", res->fullpath);

	// Check if we have an ETag file
	char *etag = load_file(res->fullpath, ".etag", res->mtime, NULL);
	if (etag == NULL)
		return NULL;

	// Check if there's a mime file
	char *content_type = load_file(res->fullpath, ".mime", res->mtime, NULL);
	if (content_type == NULL)
		return NULL;

	struct response *resp = malloc(sizeof *resp);
	if (!resp) {
		fprintf(stderr, "Failed allocating for response: %s\n", strerror(errno));
		return NULL;
	}

	resp->status = HTTP_OK;
	strncpy(resp->etag, etag, 11);
	resp->content_length = 0;
	resp->content_type = content_type;
	resp->content_encoding = "none";
	resp->content = NULL;

	// Go over all supported encodings and check if a cached version exists for
	// any of them
	for (int i = 0; i < req->num_supported_encodings - 1; i++) { // -1 because we want to avoid the "none" encoding
		char *fullpath = can_load_file(
			res->fullpath, req->supported_encodings[i].value, res->mtime, &resp->content_length);
		if (fullpath) {
			resp->content = evbuffer_new();
			if (resp->content == NULL) {
				fprintf(stderr, "Failed allocating for response buffer: %s\n", strerror(errno));
				evhttp_send_error(conn, HTTP_INTERNAL, 0);
				return NULL;
			}

			evhttp_add_header(evhttp_request_get_output_headers(conn), "Vary", "Accept-Encoding");

			int fd = open(fullpath, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "Failed opening file %s: %s\n", fullpath, strerror(errno));
				evhttp_send_error(conn, HTTP_INTERNAL, 0);
				return NULL;
			}

			evbuffer_add_file(resp->content, fd, 0, resp->content_length);
			resp->content_encoding = req->supported_encodings[i].value;
			free(fullpath);

			DEBUG_PRINT("Request will be served from cache.\n");

			return resp;
		}
	}

	return NULL;
}

char *save_response_to_cache(struct request *req,
                             struct resource *res,
                             struct response *resp,
                             unsigned char *content) {
	// Store the ETag
	if (resp->etag != NULL) {
		char *etag_file = save_file(res->fullpath, ".etag", (unsigned char *)resp->etag, 0);
		if (etag_file == NULL)
			return NULL;
		free(etag_file);
	}

	// Store the content type
	if (resp->content_type != NULL) {
		char *mime_file = save_file(res->fullpath, ".mime", (unsigned char *)resp->content_type, 0);
		if (mime_file == NULL)
			return NULL;
		free(mime_file);
	}

	// Store the content
	return save_file(res->fullpath, resp->content_encoding, content, resp->content_length);
}
