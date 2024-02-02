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
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "sheepwool.h"

enum MHD_Result serve_html(struct server_info *srv_info,
                           struct MHD_Connection *conn, struct request *req) {
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	regex_t regex;
	regmatch_t matches[3];
	long mismatch_position = -1;

	// Compile the regular expression
	if (regcomp(&regex, "<!--\\s*KEY:\\s*(.+)\\s*VALUE:\\s*(.+)\\s*-->", REG_EXTENDED)) {
		fprintf(stderr, "Could not compile regex\n");
		return 1;
	}

	FILE *file = fopen(req->res->fullpath, "rb");
	if (file == NULL) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return 0;
	}

	while ((read = getline(&line, &len, file)) != -1) {
		if (!regexec(&regex, line, 3, matches, 0)) {
			char key[matches[1].rm_eo - matches[1].rm_so + 1];
			char value[matches[2].rm_eo - matches[2].rm_so + 1];

			strncpy(key, line + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
			key[matches[1].rm_eo - matches[1].rm_so] = '\0';

			strncpy(value, line + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
			value[matches[2].rm_eo - matches[2].rm_so] = '\0';

			DEBUG_PRINT("Found HTML key %s, value %s\n", key, value);

			if (strcmp(key, "name") == 0) {
				if (res->name != NULL)
					free(res->name);
				res->name = strdup(value);
			} else if (strcmp(key, "template") == 0) {
				res->tmpl = strdup(value);
			} else if (strcmp(key, "status") == 0) {
				if (strcmp(value, "gone") == 0) {
					req->resp->status = MHD_HTTP_GONE;
				} else if (strcmp(value, "moved") == 0) {
					req->resp->status = MHD_HTTP_MOVED_PERMANENTLY;
				} else {
					req->resp->status = MHD_HTTP_OK;
				}
			} else if (strcmp(key, "tags") == 0) {
				char *tags = strdup(value);
				int i = 0;
				char *tag = strtok(tags, ", ");
				while (tag) {
					// we are allocating enough memory for one tag (or the number of tags
					// we have) plus one NULL pointer (sentinel)
					if (i > 0)
						res->tags = realloc(res->tags, sizeof(char *) * (i + 2));
					else
						res->tags = malloc(sizeof(char *) * 2);
					res->tags[i] = tag;
					tag = strtok(NULL, ", ");
					i++;
				}
				res->tags[i] = NULL;
			} else if (strcmp(key, "ctime") == 0) {
				res->ctime = strdup(value);
			} else if (strcmp(key, "mtime") == 0) {
				res->mtime = strdup(value);
			}
		} else {
			mismatch_position = ftell(res->fh);
			break;
		}
	}

	free(line);
	regfree(&regex);

	if (mismatch_position != -1) {
		// Allocate memory for the remainder of the file
		long remainder_size = res->size - mismatch_position;
		res->size -= mismatch_position;
		res->content = malloc(remainder_size + 1);
		fread(res->content, 1, remainder_size, res->fh);
		res->content[remainder_size] = '\0';
	}

	return 0;
}
