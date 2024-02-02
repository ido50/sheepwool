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

	char *new_path = malloc(new_path_len);
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

static unsigned char *load_file(
	const char *path,
	const char *extension,
	struct timespec orig_mtime,
	off_t *size) {
	unsigned char *buffer = NULL;
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

static int save_file(const char *path, const char *extension, unsigned char *buffer, off_t len) {
	int rc = 1;
	FILE *file;
	char *fullpath = add_extension(path, extension);

	file = fopen(fullpath, "w");
	if (!file) {
		fprintf(stderr, "Failed opening file %s for writing: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	if (len == 0)
		len = strlen((const char *)buffer);

	// Write the buffer to the file.
	size_t written = fwrite(buffer, 1, len, file);
	if (written < len) {
		fprintf(stderr, "Failed writing to file %s: %s\n", fullpath, strerror(errno));
		goto cleanup;
	}

	rc = 0;

cleanup:
	if (file)
		fclose(file);
	if (fullpath)
		free(fullpath);

	return rc;
}

enum MHD_Result try_serving_from_cache(
	struct server_info *srv_info,
	struct MHD_Connection *conn,
	struct request *req) {
	DEBUG_PRINT("Trying to serve %s from cache\n", req->res->fullpath);

	// Check if we have an ETag file
	unsigned char *etag = load_file(req->res->fullpath, ".etag", req->res->mtime, NULL);
	if (etag == NULL)
		return MHD_NO;

	// Check if there's a mime file
	unsigned char *content_type = load_file(req->res->fullpath, ".mime", req->res->mtime, NULL);
	if (content_type == NULL)
		return MHD_NO;

	req->resp = malloc(sizeof *req->resp);
	req->resp->status = MHD_HTTP_OK;
	req->resp->size = 0;
	req->resp->etag = etag;
	req->resp->location = NULL;
	req->resp->content_type = content_type;
	req->resp->content = NULL;
	req->resp->backend = NULL;
	req->resp->content_encoding = "none";

	// Go over all supported encodings and check if a cached version exists for
	// any of them
	for (int i = 0; i < req->num_supported_encodings - 1; i++) { // -1 because we want to avoid the "none" encoding
		req->resp->content = load_file(
			req->res->fullpath, req->supported_encodings[i].value, req->res->mtime, &req->resp->size);
		if (req->resp->content != NULL) {
			req->resp->content_encoding = req->supported_encodings[i].value;
			break;
		}
	}

	if (req->resp->content == NULL)
		return MHD_NO;

	req->resp->backend = MHD_create_response_from_buffer(
		req->resp->size, req->resp->content, MHD_RESPMEM_PERSISTENT);
	if (req->resp->backend == NULL) {
		fprintf(stderr, "Failed creating response from buffer: %s\n", strerror(errno));
		return MHD_NO;
	}

	MHD_add_response_header(req->resp->backend, "ETag", (const char *)req->resp->etag);
	MHD_add_response_header(req->resp->backend, "Content-Encoding", req->resp->content_encoding);
	MHD_add_response_header(req->resp->backend, "Content-Type", (const char *)req->resp->content_type);

	enum MHD_Result ret = MHD_queue_response(conn, req->resp->status, req->resp->backend);
	if (ret == MHD_YES)
		DEBUG_PRINT("Successfully served %s from cache\n", req->dec_path);
	return ret;
}

int save_response_to_cache(struct server_info *srv_info, struct request *req) {
	if (req->resp->content_encoding == NULL || strcmp(req->resp->content_encoding, "none") == 0) {
		DEBUG_PRINT("Not saving resource %s to cache because we did not compress it\n", req->dec_path);
		return 0;
	}

	int rc = 0;

	// Store the ETag
	if (req->resp->etag != NULL) {
		rc = save_file(req->res->fullpath, ".etag", req->resp->etag, 0);
		if (rc)
			return rc;
	}

	// Store the content type
	if (req->resp->content_type != NULL) {
		rc = save_file(req->res->fullpath, ".mime", req->resp->content_type, 0);
		if (rc)
			return rc;
	}

	// Store the content
	if (req->resp->size > 0) {
		rc = save_file(req->res->fullpath, req->resp->content_encoding, req->resp->content, req->resp->size);
		if (rc)
			return rc;
	}

	if (rc == 0)
		DEBUG_PRINT("Successfully saved %s to cache", req->dec_path);
	else
		DEBUG_PRINT("Failed saving %s to cache", req->dec_path);

	return rc;
}
