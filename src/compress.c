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
#include <hiredis/hiredis.h>
#include <pcre.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if HAVE_BROTLI
#include <brotli/encode.h>
#endif
#if HAVE_LIBZ
#include <zlib.h>
#endif

#include "sheepwool.h"

#define CHUNK 16384

bool is_compressible(const char *mime) {
	if (strncmp(mime, "text/", 5) == 0)
		return true;

	if (has_suffix(mime, "json") || has_suffix(mime, "xml"))
		return true;

	const char *exact_checks[] = {
		"application/javascript",
	};

	size_t num_exact = sizeof(exact_checks) / sizeof(exact_checks[0]);

	for (size_t i = 0; i < num_exact; i++)
		if (strcmp(mime, exact_checks[i]) == 0)
			return true;

	return false;
}

#ifdef HAVE_BROTLI
static int compress_brotli(struct server_info *srv_info, struct request *req) {
	FILE *file = fopen(req->res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return 1;
	}

	unsigned char *uncompressed = (unsigned char*)malloc(req->res->size);
	if (!uncompressed) {
		fprintf(stderr, "Memory allocation failed: %s\n", strerror(errno));
		fclose(file);
		return 1;
	}

	fread(uncompressed, 1, req->res->size, file);
	fclose(file);

	size_t buffer_size = BrotliEncoderMaxCompressedSize(req->res->size);
	req->resp->content = (unsigned char*)malloc(buffer_size);
	if (!req->resp->content) {
		fprintf(stderr, "Failed allocating memory for compressed data: %s\n", strerror(errno));
		return 1;
	}

	size_t compressed_size;
	if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
	                           req->res->size, uncompressed, &compressed_size, req->resp->content)) {

		fprintf(stderr, "Failed compressing with brotli: %s\n", strerror(errno));
		return 1;
	}

	req->resp->size = (off_t)compressed_size;
	req->resp->content_encoding = "br";

	return 0;
}
#endif

#ifdef HAVE_LIBZ
static int compress_deflate(struct server_info *srv_info, struct request *req) {
	FILE *file = fopen(req->res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return 1;
	}

	unsigned char *uncompressed = (unsigned char*)malloc(req->res->size);
	if (!uncompressed) {
		fprintf(stderr, "Memory allocation failed: %s\n", strerror(errno));
		fclose(file);
		return 1;
	}

	fread(uncompressed, 1, req->res->size, file);
	fclose(file);

	unsigned long buffer_size = compressBound(req->res->size);
	req->resp->content = (unsigned char*)malloc(buffer_size);
	if (!req->resp->content) {
		fprintf(stderr, "Memory allocation failed for compressed buffer: %s\n", strerror(errno));
		free(req->resp->content);
		req->resp->content = NULL;
		return 1;
	}

	// Compress the file content
	if (compress2(req->resp->content, &buffer_size, uncompressed, req->res->size, Z_BEST_COMPRESSION) != Z_OK) {
		fprintf(stderr, "Failed compressing %s with deflate: %s\n", req->res->fullpath, strerror(errno));
		free(req->resp->content);
		req->resp->content = NULL;
		return 1;
	}

	req->resp->size = buffer_size;
	req->resp->content_encoding = "deflate";

	return 0;
}
#endif

static int compare_encodings(const void* a, const void* b) {
	double weight_a = ((struct header_choice*)a)->weight;
	double weight_b = ((struct header_choice*)b)->weight;
	return (weight_a < weight_b) - (weight_a > weight_b);
}

void parse_accept_encoding(struct request *req) {
	const char *error;
	int erroffset;
	pcre *re = NULL;
	int ovector[MAX_ENCODINGS+1];
	const char* pattern = "([^,;\\s]+)\\s*(?:;\\s*q=([01]\\.\\d{0,3}|1\\.0{0,3}|0))?";

	struct param *param;
	HASH_FIND_STR(req->headers, "accept-encoding", param);

	if (
		param == NULL ||
		param->value == NULL ||
		strcmp(param->value, "") == 0) {

		DEBUG_PRINT("Client does not accept any encoding\n");
		goto cleanup;
	}

	DEBUG_PRINT("Accept-Encoding sent by client: %s\n", param->value);

	// Compile the regex pattern
	re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
		goto cleanup;
	}

	const char* subject = param->value;
	int subject_length = strlen(subject);
	int start_offset = 0;

	int rc;
	while ((rc = pcre_exec(re, NULL, subject, subject_length, start_offset, 0, ovector, MAX_ENCODINGS)) >= 0) {
		for (int i = 1; i < rc; i++) {
			const char *match;
			pcre_get_substring(subject, ovector, rc, i, &match);
			if (i == 1) {
				req->supported_encodings[req->num_supported_encodings].value = match;
			} else if (i == 2 && match != NULL) { // Weight, if present
				req->supported_encodings[req->num_supported_encodings].weight = strtod(match, NULL);
			}
		}

		start_offset = ovector[1]; // Move past the end of the previous match
		req->num_supported_encodings++;
	}

	qsort(req->supported_encodings, req->num_supported_encodings, sizeof(struct header_choice), compare_encodings);

cleanup:
	req->supported_encodings[req->num_supported_encodings].value = "none";
	req->supported_encodings[req->num_supported_encodings++].weight = 0;

	if (re != NULL) {
		/*for (int i = 0; i < req->num_supported_encodings - 1; i++)*/
		/*pcre_free_substring(req->supported_encodings[i].value);*/
		pcre_free(re);
	}
}

bool compress_file(struct server_info *srv_info, struct request *req) {
	for (int i = 0; i < req->num_supported_encodings - 1; i++) {
#ifdef HAVE_BROTLI
		if (strcmp(req->supported_encodings[i].value, "br") == 0) {
			int rc = compress_brotli(srv_info, req);
			if (rc)
				continue;
			DEBUG_PRINT("Compressed with brotli to %lo bytes\n", req->resp->size);
			return true;
		}
#endif

#ifdef HAVE_LIBZ
		if (strcmp(req->supported_encodings[i].value, "deflate") == 0) {
			int rc = compress_deflate(srv_info, req);
			if (rc)
				continue;
			DEBUG_PRINT("Compressed with deflate to %lo bytes\n", req->resp->size);
			return true;
		}
#endif
	}

	return false;
}
