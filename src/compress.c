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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
static unsigned char *compress_brotli(struct server_info *srv_info,
                                      struct request *req,
                                      struct resource *res,
                                      struct response *resp) {
	DEBUG_PRINT("Trying to compress %s with brotli", res->fullpath);

	FILE *file = fopen(res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", res->fullpath, strerror(errno));
		return NULL;
	}

	unsigned char *uncompressed = malloc(res->size);
	if (!uncompressed) {
		fprintf(stderr, "Memory allocation failed: %s\n", strerror(errno));
		fclose(file);
		return NULL;
	}

	fread(uncompressed, 1, res->size, file);
	fclose(file);

	size_t buffer_size = BrotliEncoderMaxCompressedSize(res->size);
	unsigned char *content = malloc(buffer_size);
	if (content == NULL) {
		fprintf(stderr, "Failed allocating memory for compressed data: %s\n", strerror(errno));
		return NULL;
	}

	size_t compressed_size;
	if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
	                           res->size, uncompressed, &compressed_size, content)) {

		fprintf(stderr, "Failed compressing with brotli: %s\n", strerror(errno));
		return NULL;
	}

	resp->content_length = compressed_size;
	resp->content_encoding = "br";

	return content;
}
#endif

#ifdef HAVE_LIBZ
static unsigned char *compress_deflate(
	struct server_info *srv_info,
	struct request *req,
	struct resource *res,
	struct response *resp) {
	DEBUG_PRINT("Trying to compress %s with deflate", res->fullpath);

	FILE *file = fopen(res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", res->fullpath, strerror(errno));
		return NULL;
	}

	unsigned char *uncompressed = malloc(res->size);
	if (!uncompressed) {
		fprintf(stderr, "Failed allocating for uncompressed data: %s\n", strerror(errno));
		fclose(file);
		return NULL;
	}

	fread(uncompressed, 1, res->size, file);
	fclose(file);

	unsigned long buffer_size = compressBound(res->size);

	unsigned char *content = malloc(buffer_size);
	if (!content) {
		fprintf(stderr, "Memory allocation failed for compressed content: %s\n", strerror(errno));
		return NULL;
	}

	// Compress the file content
	if (compress2(content, &buffer_size, uncompressed, res->size, Z_BEST_COMPRESSION) != Z_OK) {
		fprintf(stderr, "Failed compressing %s with deflate: %s\n", res->fullpath, strerror(errno));
		free(content);
		return NULL;
	}

	resp->content_length = buffer_size;
	resp->content_encoding = "deflate";

	return content;
}

static unsigned char *compress_gzip(
	struct server_info *srv_info,
	struct request *req,
	struct resource *res,
	struct response *resp) {
	DEBUG_PRINT("Trying to compress %s with gzip", res->fullpath);

	FILE *file = fopen(res->fullpath, "rb");
	if (!file) {
		fprintf(stderr, "Failed opening file %s: %s\n", res->fullpath, strerror(errno));
		return NULL;
	}

	unsigned char *uncompressed = malloc(res->size);
	if (!uncompressed) {
		fprintf(stderr, "Failed allocating for uncompressed data: %s\n", strerror(errno));
		fclose(file);
		return NULL;
	}

	fread(uncompressed, 1, res->size, file);
	fclose(file);

	unsigned long compressed_size = compressBound(res->size) + 18; // Add 18 bytes for the gzip header and trailer
	unsigned char *compressed = malloc(compressed_size);
	if (!compressed) {
		fprintf(stderr, "Failed allocating for compressed data: %s\n", strerror(errno));
		return NULL;
	}

	z_stream stream;
	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;
	stream.avail_in = res->size;
	stream.next_in = uncompressed;
	stream.avail_out = compressed_size;
	stream.next_out = compressed;

	// Initialize gzip encoding
	if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		fprintf(stderr, "Failed initializing deflate stream: %s\n", stream.msg);
		free(uncompressed);
		free(compressed);
		return NULL;
	}

	// Compress the file
	if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
		fprintf(stderr, "Failed compressing %s with gzip: %s\n", res->fullpath, stream.msg);
		deflateEnd(&stream);
		free(uncompressed);
		free(compressed);
		return NULL;
	}

	compressed_size = stream.total_out;

	if (deflateEnd(&stream) != Z_OK) {
		fprintf(stderr, "Failed compressing %s with gzip: %s\n", res->fullpath, stream.msg);
		free(uncompressed);
		free(compressed);
		return NULL;
	}

	free(uncompressed);

	resp->content_length = compressed_size;
	resp->content_encoding = "gzip";

	return compressed;
}
#endif

unsigned char *compress_file(struct server_info *srv_info,
                             struct request *req,
                             struct resource *res,
                             struct response *resp) {
	for (int i = 0; i < req->num_supported_encodings - 1; i++) {
		DEBUG_PRINT("Client accepts %s\n", req->supported_encodings[i].value);

#ifdef HAVE_BROTLI
		if (strcmp(req->supported_encodings[i].value, "br") == 0) {
			unsigned char *content = compress_brotli(srv_info, req, res, resp);
			if (content == NULL)
				continue;
			DEBUG_PRINT("Compressed with brotli to %lo bytes\n", resp->content_length);
			return content;
		}
#endif

#ifdef HAVE_LIBZ
		if (strcmp(req->supported_encodings[i].value, "gzip") == 0) {
			unsigned char *content = compress_gzip(srv_info, req, res, resp);
			if (content == NULL)
				continue;
			DEBUG_PRINT("Compressed with gzip to %lo bytes\n", resp->content_length);
			return content;
		}

		if (strcmp(req->supported_encodings[i].value, "deflate") == 0) {
			unsigned char *content = compress_deflate(srv_info, req, res, resp);
			if (content == NULL)
				continue;
			DEBUG_PRINT("Compressed with deflate to %lo bytes\n", resp->content_length);
			return content;
		}
#endif
	}

	return NULL;
}
