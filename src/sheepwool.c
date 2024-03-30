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

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <fcntl.h>
#include <libconfig.h>
#include <libgen.h>
#include <magic.h>
#include <netinet/in.h>
#include <pcre.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "cmdline.h"
#include "sheepwool.h"

extern int pledge(const char *promises, const char *execpromises);
extern int unveil(const char *path, const char *permissions);

static size_t max_date_size = strlen("18/Sep/2011:19:18:28 -0400") + 6;

struct all_structs {
	struct request *req;
	struct resource *res;
	struct response *resp;
};

static void free_request(struct evhttp_request *conn, void *arg) {
	struct all_structs *structs = arg;

	if (structs->req != NULL) {
		if (structs->req->uri != NULL)
			evhttp_uri_free(structs->req->uri);

		if (structs->req->path != NULL)
			free(structs->req->path);

		if (structs->req->num_supported_encodings)
			for (int i = 0; i < structs->req->num_supported_encodings - 1; i++)
				pcre_free_substring(structs->req->supported_encodings[i].value);

		free(structs->req);
	}

	if (structs->res != NULL) {
		if (structs->res->fullpath != NULL)
			free(structs->res->fullpath);
		free(structs->res);
	}

	if (structs->resp != NULL) {
		if (structs->resp->content != NULL)
			evbuffer_free(structs->resp->content);
		free(structs->resp);
	}

	free(structs);
}

bool has_suffix(const char *string, const char *suffix) {
	if (string == NULL || suffix == NULL) return false;

	size_t string_len = strlen(string);
	size_t suffix_len = strlen(suffix);

	if (suffix_len > string_len) return false;

	// Compare the end of the string with the suffix
	return strncmp(string + string_len - suffix_len, suffix, suffix_len) == 0;
}

static char *get_fullpath(struct request *req) {
	int len_prefix = 2; // length of ./ prefix
	int len_path = strlen(req->path);
	int len = len_prefix + len_path + 1; // 1 for NULL terminator

	// if path has a trailing slash, remove it
	if (len_path > 1 && req->path[len_path - 1] == '/')
		len -= 1;

	char *fullpath = NULL;

	if (true) {
		// remove heading slash
		char *path = req->path;
		if (path[0] == '/') {
			len -= 1;
			path = path + 1;
		}

		fullpath = malloc(len);
		if (fullpath == NULL) {
			fprintf(stderr, "Failed allocating %d bytes for fullpath: %s\n", len, strerror(errno));
			return NULL;
		}

		stpcpy(stpcpy(fullpath, "./"), path);

		return fullpath;
	}

	// account for the host
	len += strlen(req->host);

	// we need a heading slash when we have a host
	if (req->path[0] != '/')
		len++;

	fullpath = malloc(len);
	if (fullpath == NULL) {
		fprintf(stderr, "Failed allocating %d bytes for fullpath: %s\n", len, strerror(errno));
		return NULL;
	}

	char *p = stpcpy(fullpath, "./");
	p = stpcpy(p, req->host);
	if (req->path[0] != '/')
		p = stpcpy(p, "/");
	stpcpy(p, req->path);

	return fullpath;
}

static struct resource *locate_resource_in_fs(struct request *req, char *fullpath, bool exact) {
	if (fullpath == NULL) {
		fullpath = get_fullpath(req);
		if (fullpath == NULL) {
			DEBUG_PRINT("Full path is NULL\n");
			return NULL;
		}
	}

	DEBUG_PRINT("Looking for %s, exact=%d\n", fullpath, exact);

	struct stat fstat;
	int rc = lstat(fullpath, &fstat);
	int err = errno;
	if (rc == -1) {
		if (err != ENOENT) {
			fprintf(stderr, "Failed running lstat on %s: %s\n", fullpath, strerror(err));
			return NULL;
		}

		if (exact) {
			DEBUG_PRINT("%s not found in exact mode\n", fullpath);
			return NULL;
		}

		// Try with .html
		fullpath = realloc(fullpath, strlen(fullpath) + 5 + 1);
		if (fullpath == NULL) {
			fprintf(stderr, "Failed reallocing fullpath: %s\n", strerror(errno));
			abort();
		}
		strcat(fullpath, ".html");
		return locate_resource_in_fs(req, fullpath, true);
	}

	if (S_ISDIR(fstat.st_mode)) {
		// This is a directory, look for an index.html file in it
		int newlen = strlen(fullpath) + (fullpath[strlen(fullpath)-1] == '/' ? 10 : 11) + 1;
		fullpath = realloc(fullpath, newlen);
		if (fullpath == NULL) {
			fprintf(stderr, "Failed reallocing fullpath: %s\n", strerror(errno));
			return NULL;
		}

		if (fullpath[strlen(fullpath)-1] == '/')
			strcat(fullpath, "index.html");
		else
			strcat(fullpath, "/index.html");

		struct resource *index_html = locate_resource_in_fs(req, fullpath, true);
		if (index_html != NULL)
			return index_html;

		// Try index.psgi
		fullpath[newlen - 5] = 'p';
		fullpath[newlen - 4] = 's';
		fullpath[newlen - 3] = 'g';
		fullpath[newlen - 2] = 'i';

		return locate_resource_in_fs(req, fullpath, true);
	}

	// If this is a regular file, we can serve it directly, just make sure we have
	// access to it
	if (S_ISREG(fstat.st_mode) && access(fullpath, F_OK) == 0) {
		DEBUG_PRINT("Found %s and it is accessible\n", fullpath);
		struct resource *res = malloc(sizeof *res);
		if (res == NULL) {
			fprintf(stderr, "Failed allocating for resource: %s\n", strerror(errno));
			return NULL;
		}

		res->fullpath = fullpath;
		res->type = has_suffix(fullpath, ".psgi")
      ? PSGI
      : has_suffix(fullpath, ".html")
      ? HTML
      : STAT;
		res->size = fstat.st_size;
		res->mtime = fstat.st_mtim;
		return res;
	}

	DEBUG_PRINT("%s found but is not a regular file\n", fullpath);

	return NULL;
}

static void write_access_log(struct evhttp_request *conn,
                             struct request *req, struct response *resp) {
	char date[max_date_size];
	time_t now = time(NULL);
	if (now != -1) {
		struct tm *nowinfo = localtime(&now);
		strftime(date, max_date_size, "%d/%b/%Y:%T %z", nowinfo);
	} else {
		snprintf(date, max_date_size, "unknown");
	}

	const char *remote = req->remote_addr;
	if (remote == NULL)
		remote = "-";

	struct evkeyvalq *headers = evhttp_request_get_input_headers(conn);

	const char *referer = evhttp_find_header(headers, "Referer");
	if (!referer) referer = "";

	const char *user_agent = evhttp_find_header(headers, "User-Agent");
	if (!user_agent) user_agent = "";

	fprintf(stdout, "%s %s - - [%s] \"%s %s %s\" %d %ld \"%s\" \"%s\"\n",
	        req->host,
	        remote,
	        date,
	        req->method_str,
	        req->path,
	        "HTTP/1.1",
	        resp->status,
	        resp->content_length,
	        referer,
	        user_agent);
}

static int compare_encodings(const void *a, const void *b) {
	double weight_a = ((struct header_choice*)a)->weight;
	double weight_b = ((struct header_choice*)b)->weight;
	return (weight_a < weight_b) - (weight_a > weight_b);
}

static void parse_accept_encoding(struct evhttp_request *conn,
                                  struct request *req) {
	const char *error;
	int erroffset;
	pcre *re = NULL;
	int ovector[MAX_ENCODINGS+1];
	const char *pattern = "([^,;\\s]+)\\s*(?:;\\s*q=([01]\\.\\d{0,3}|1\\.0{0,3}|0))?";

	const char *value = evhttp_find_header(evhttp_request_get_input_headers(conn), "Accept-Encoding");
	if (value == NULL || strcmp(value, "") == 0) {
		DEBUG_PRINT("Client does not accept any encoding\n");
		goto cleanup;
	}

	DEBUG_PRINT("Accept-Encoding sent by client: %s\n", value);

	// Compile the regex pattern
	re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
	if (re == NULL) {
		fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
		goto cleanup;
	}

	const char *subject = value;
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
		pcre_free(re);
	}
}

static struct request *init_request(struct evhttp_request *conn) {
	struct request *req = malloc(sizeof *req);
	if (req == NULL) {
		fprintf(stderr, "Failed allocating for request: %s\n", strerror(errno));
		return NULL;
	}

	req->uri = NULL;
	req->path = NULL;

	// Decode the URI
	req->uri = evhttp_uri_parse(evhttp_request_get_uri(conn));
	if (!req->uri)
		return NULL;

	req->host = evhttp_request_get_host(conn);

	const char *raw_path = evhttp_uri_get_path(req->uri);
	if (!raw_path)
		raw_path = "/";

	req->path = evhttp_uridecode(raw_path, 0, NULL);
	if (req->path == NULL)
		return NULL;

	req->method = evhttp_request_get_command(conn);

	switch (req->method) {
	case EVHTTP_REQ_GET:
		req->method_str = "GET";
		break;
	case EVHTTP_REQ_PUT:
		req->method_str = "PUT";
		break;
	case EVHTTP_REQ_POST:
		req->method_str = "POST";
		break;
	case EVHTTP_REQ_PATCH:
		req->method_str = "PATCH";
		break;
	case EVHTTP_REQ_DELETE:
		req->method_str = "DELETE";
		break;
	case EVHTTP_REQ_OPTIONS:
		req->method_str = "OPTIONS";
		break;
	case EVHTTP_REQ_HEAD:
		req->method_str = "HEAD";
		break;
	case EVHTTP_REQ_TRACE:
		req->method_str = "TRACE";
		break;
	case EVHTTP_REQ_CONNECT:
		req->method_str = "CONNECT";
		break;
	}

	req->is_safe = req->method == EVHTTP_REQ_GET ||
	               req->method == EVHTTP_REQ_HEAD ||
	               req->method == EVHTTP_REQ_OPTIONS;

	evhttp_connection_get_peer(evhttp_request_get_connection(conn), &req->remote_addr, &req->remote_port);

	req->delegate = NULL;
	req->input = 0;

	req->num_supported_encodings = 0;
	memset(req->supported_encodings, 0, sizeof(req->supported_encodings));

	// Parse the Accept-Encoding header so we know which compression algorithms
	// the client supports
	parse_accept_encoding(conn, req);

	return req;
}

static void handle_req(struct evhttp_request *conn, void *arg) {
	struct server_info *srv_info = arg;
	struct request *req = NULL;
	struct resource *res = NULL;
	struct response *resp = NULL;

	struct all_structs *structs = malloc(sizeof *structs);
	if (structs == NULL) {
		fprintf(stderr, "Failed allocating for structs: %s\n", strerror(errno));
		evhttp_send_error(conn, HTTP_INTERNAL, 0);
		return;
	}

	structs->req = req;
	structs->res = res;
	structs->resp = resp;

	evhttp_request_set_on_complete_cb(conn, free_request, structs);

	req = init_request(conn);
	if (req == NULL) {
		evhttp_send_error(conn, HTTP_INTERNAL, 0);
		return;
	}

	structs->req = req;

	if (strstr(req->path, "..")) {
		evhttp_send_error(conn, HTTP_BADREQUEST, 0);
		return;
	}

	res = locate_resource_in_fs(req, NULL, false);
	if (res == NULL) {
		evhttp_send_error(conn, HTTP_NOTFOUND, 0);
		return;
	}

	structs->res = res;

	if (!req->is_safe && res->type != PSGI) {
		evhttp_send_error(conn, HTTP_BADMETHOD, 0);
		return;
	}

	// If request is safe, try serving it from cache.
	if (req->method == EVHTTP_REQ_GET || req->method == EVHTTP_REQ_HEAD)
		resp = try_serving_from_cache(srv_info, conn, req, res);

	// Serving from cache failed, let's serve the file based on its type.
	if (!resp) {
		switch (res->type) {
		case PSGI:
			resp = serve_psgi(srv_info, conn, req, res);
			break;
		case HTML:
			resp = serve_html(srv_info, conn, req, res);
			break;
		default:
			resp = serve_file(srv_info, conn, req, res);
		}
	}

	if (!resp) {
		evhttp_send_error(conn, HTTP_INTERNAL, 0);
		return;
	}

	structs->resp = resp;

	struct evkeyvalq *headers = evhttp_request_get_output_headers(conn);

	if (resp->content_length) {
		char content_length[21];
		snprintf(content_length, 21, "%ld", resp->content_length);
		evhttp_add_header(headers, "Content-Length", content_length);
		evhttp_add_header(headers, "Content-Type", resp->content_type);
	}

	if (resp->content_encoding && strcmp(resp->content_encoding, "none") != 0)
		evhttp_add_header(headers, "Content-Encoding", resp->content_encoding);

	if (strlen(resp->etag))
		evhttp_add_header(headers, "ETag", resp->etag);

	if (req->method == EVHTTP_REQ_HEAD && resp->content != NULL)
		evbuffer_drain(resp->content, evbuffer_get_length(resp->content));

	evhttp_send_reply(conn, resp->status, "OK", resp->content);

	write_access_log(conn, req, resp);
}

static int sandbox(char *root) {
	int rc = 0;

	if (HAVE_PLEDGE) {
		rc = pledge("unix sendfd recvfd inet dns proc stdio rpath wpath cpath "
		            "flock fattr unveil",
		            NULL);
		if (rc == -1) {
			fprintf(stderr, "Failed pledging: %s\n", strerror(errno));
			return rc;
		}
	}

	if (HAVE_UNVEIL) {
		rc = unveil(root, "rwc");
		if (rc == -1) {
			fprintf(stderr, "Failed unveiling source directory: %s\n", strerror(errno));
			return rc;
		}

		rc = unveil("/usr/local/share/misc/magic.mgc", "r");
		if (rc == -1) {
			fprintf(stderr, "Failed unveiling magic database: %s\n", strerror(errno));
			return rc;
		}

		rc = unveil(NULL, NULL);
		if (rc == -1) {
			fprintf(stderr, "Failed closing unveil: %s\n", strerror(errno));
			return rc;
		}
	}

	return 0;
}

static int load_config(struct server_info *srv_info) {
	config_t config;
	config_init(&config);

	int rc = config_read_file(&config, "sheepwool.conf");
	if (rc != CONFIG_TRUE) {
		fprintf(stderr, "WARN: Failed parsing config file %s [%d]: %s\n", config_error_file(&config), config_error_line(&config), config_error_text(&config));
		config_destroy(&config);
		return 1;
	}

	srv_info->ignore = NULL;
	config_setting_t *ignore = config_lookup(&config, "ignore");
	if (ignore != NULL) {
		int count = config_setting_length(ignore);
		srv_info->ignore = malloc(sizeof(char *)*count);
		if (srv_info->ignore == NULL) {
			fprintf(stderr, "Failed allocating memory for ignore array: %s\n", strerror(errno));
			return 1;
		}

		for (int i = 0; i < count; i++)
			srv_info->ignore[i] = strdup(config_setting_get_string_elem(ignore, i));
	}

	const char *handler;
	if (config_lookup_string(&config, "html_handler", &handler))
		srv_info->html_handler = strdup(handler);

	return 0;
}

static int load_magic_db(struct server_info *srv_info) {
	srv_info->magic_db = magic_open(MAGIC_MIME_TYPE);
	if (srv_info->magic_db == NULL) {
		fprintf(stderr, "Failed opening libmagic cookie: %s\n", strerror(errno));
		return 1;
	}

	if (magic_load(srv_info->magic_db, NULL) != 0) {
		fprintf(stderr, "Failed loading libmagic DB: %s\n",
		        magic_error(srv_info->magic_db));
		return 1;
	}

	return 0;
}

static char *get_root_directory(struct gengetopt_args_info *params) {
	char *root;
	char *cwd = getcwd(NULL, 0);
	if ( cwd == NULL ){
		fprintf(stderr, "Failed getting current working directory: %s\n", strerror(errno));
		return NULL;
	}

	root = params->inputs ? params->inputs[0] : cwd;

	// Remove trailing slash from root, if exists
	int root_len = strlen(root);
	if (root[root_len - 1] == '/')
		root[root_len - 1] = '\0';

	// Change current working directory to the root directory we are serving
	// (unless we are serving the CWD)
	if (strcmp(root, cwd) != 0) {
		DEBUG_PRINT("Changing directory to %s\n", root);
		int rc = chdir(root);
		if (rc) {
			fprintf(stderr, "Failed changing directory: %s\n", strerror(errno));
			return NULL;
		}
	}

	return root;
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	printf("%s signal received\n", strsignal(fd));
	event_base_loopbreak(arg);
}

int main(int argc, char **argv, char **env) {
	struct server_info srv_info;
	srv_info.html_handler = NULL;

	struct event_base *base;
	struct evhttp *http_server;
	struct event *sig_int;

	// Parse command line arguments
	struct gengetopt_args_info params;
	int rc = cmdline_parser(argc, argv, &params);
	if ( rc != 0 )
		goto cleanup;

	DEBUG_PRINT("Starting perl interpreter...\n");
	rc = start_perl(argc, argv, env);
	if (rc)
		goto cleanup;
	DEBUG_PRINT("Perl interpreter started.\n");

	// Determine the root directory we are saving, and chdir to it if necessary
	char *root = get_root_directory(&params);
	if ( root == NULL ) {
		rc = 1;
		goto cleanup;
	}

	// On OpenBSD, sandbox the application with pledge and unveil
	rc = sandbox(root);
	if (rc)
		goto cleanup;

	// Load the Magic MIME database which is used by the server
	rc = load_magic_db(&srv_info);
	if (rc)
		goto cleanup;

	// Load configuration
	load_config(&srv_info);

	// Start the HTTP server
	DEBUG_PRINT("Starting HTTP server...\n");

	base = event_base_new();
	http_server = evhttp_new(base);
	evhttp_set_allowed_methods(http_server, EVHTTP_REQ_GET|EVHTTP_REQ_POST|EVHTTP_REQ_HEAD|EVHTTP_REQ_PUT|EVHTTP_REQ_DELETE|EVHTTP_REQ_OPTIONS|EVHTTP_REQ_PATCH);
	evhttp_bind_socket(http_server, "0.0.0.0", params.port_arg);
	evhttp_set_gencb(http_server, handle_req, &srv_info);

	sig_int = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(sig_int, NULL);

	fprintf(stderr, "Listening for requests on http://0.0.0.0:%d\n", params.port_arg);

	event_base_dispatch(base);

cleanup:
	fprintf(stderr, "Shutting down server...\n");

	evhttp_free(http_server);
	event_free(sig_int);
	event_base_free(base);

	if (srv_info.magic_db != NULL)
		magic_close(srv_info.magic_db);

	if (srv_info.html_handler != NULL)
		free(srv_info.html_handler);

	destroy_perl();

	exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
}
