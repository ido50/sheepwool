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
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libconfig.h>
#include <libgen.h>
#include <magic.h>
#include <microhttpd.h>
#include <netinet/in.h>
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
#include <utarray.h>
#include <uthash.h>
#include <zlib.h>

#include "cmdline.h"
#include "sheepwool.h"

extern int pledge(const char *promises, const char *execpromises);
extern int unveil(const char *path, const char *permissions);

static size_t max_date_size = strlen("18/Sep/2011:19:18:28 -0400") + 6;

void request_completed(void *cls, struct MHD_Connection *connection,
                       void **con_cls, enum MHD_RequestTerminationCode toe) {
	if (*con_cls == NULL)
		return;

	struct request *req = *con_cls;

	if (req->dec_path != NULL)
		curl_free(req->dec_path);

	if (req->url != NULL)
		curl_url_cleanup(req->url);

	if (req->remote != NULL)
		free(req->remote);

	if (req->headers != NULL) {
		struct param *current_header, *tmp;

		HASH_ITER(hh, req->headers, current_header, tmp) {
			HASH_DEL(req->headers, current_header);
			free(current_header);
		}
	}

	if (req->postprocessor != NULL)
		MHD_destroy_post_processor(req->postprocessor);

	if (req->body_params != NULL) {
		struct body_param *current_param, *tmp;

		HASH_ITER(hh, req->body_params, current_param, tmp) {
			HASH_DEL(req->body_params, current_param);
			if (current_param->type == ARRAY)
				utarray_free(current_param->array_value);
			free(current_param);
		}
	}

	if (req->res != NULL) {
		free(req->res->fullpath);
		free(req->res);
	}

	if (req->resp != NULL) {
		if (req->resp->backend != NULL)
			MHD_destroy_response(req->resp->backend);
		if (req->resp->content_type != NULL)
			free(req->resp->content_type);
		if (req->resp->content != NULL)
			free(req->resp->content);
		free(req->resp);
	}

	free(req);

	*con_cls = NULL;
}

bool has_suffix(const char *string, const char *suffix) {
	if (string == NULL || suffix == NULL) return false;

	size_t string_len = strlen(string);
	size_t suffix_len = strlen(suffix);

	if (suffix_len > string_len) return false;

	// Compare the end of the string with the suffix
	return strncmp(string + string_len - suffix_len, suffix, suffix_len) == 0;
}

static enum MHD_Result collect_param(void *coninfo_cls, enum MHD_ValueKind kind,
                                     const char *key, const char *value) {
	struct request *req = coninfo_cls;

	struct body_param *param = NULL;
	HASH_FIND_STR(req->body_params, key, param);

	if (param == NULL) {
		// new string parameter
		param = malloc(sizeof *param);
		param->name = key;
		param->string_value = value;
		param->type = STRING;
		HASH_ADD_STR(req->body_params, name, param);
		return MHD_YES;
	}

	if (param->type == ARRAY) {
		// Push to an existing array
		utarray_push_back(param->array_value, value);
	} else {
		// Turn existing string into an array and push new value
		param->type = ARRAY;
		utarray_new(param->array_value, &ut_str_icd);
		utarray_push_back(param->array_value, param->string_value);
		utarray_push_back(param->array_value, value);
	}

	return MHD_YES;
}

static enum MHD_Result build_qs(void *coninfo_cls, enum MHD_ValueKind kind,
                                const char *key, const char *value) {
	struct request *req = coninfo_cls;

	size_t part_len = strlen(key)+1+strlen(value)+1;
	char part[part_len];
	snprintf(part, part_len, "%s=%s", key, value);
	curl_url_set(req->url, CURLUPART_QUERY, part, CURLU_APPENDQUERY);

	return MHD_YES;
}

static enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                                    const char *key, const char *filename,
                                    const char *content_type, const char *transfer_encoding,
                                    const char *value, uint64_t off, size_t size) {
	if (kind == MHD_POSTDATA_KIND)
		return collect_param(coninfo_cls, kind, key, value);

	return MHD_YES;
}

static enum MHD_Result parse_header(void *cls, enum MHD_ValueKind kind, const char *key,
                                    const char *value) {
	struct request *req = cls;
	int len = strlen(key);

	char *header_name = malloc(len+1);
	for (int i = 0; i <= len-1; i++)
		header_name[i] = tolower(key[i]);
	header_name[len] = '\0';

	struct param *header = malloc(sizeof *header);
	header->name = header_name;
	header->value = value;

	HASH_ADD_STR(req->headers, name, header);

	return MHD_YES;
}

static struct resource *locate_resource_in_fs(struct request *req, char *fullpath, bool exact) {
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
		fullpath = realloc(fullpath, strlen(fullpath) + 4 + 1);
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

static char *get_fullpath(struct request *req, const char *path) {
	int len_prefix = 2; // length of ./ prefix
	int len_path = strlen(path);
	int len = len_prefix + len_path + 1; // 1 for NULL terminator

	// if path has a trailing slash, remove it
	if (len_path > 1 && path[len_path - 1] == '/')
		len -= 1;

	char *fullpath = NULL;

	if (true) {
		// remove heading slash
		if (path[0] == '/') {
			len -= 1;
			path = path + 1;
		}

		fullpath = malloc(len);
		if (fullpath == NULL)
			return NULL;

		stpcpy(stpcpy(fullpath, "./"), path);

		return fullpath;
	}

	// account for the host
	len += strlen(req->host);

	// we need a heading slash when we have a host
	if (path[0] != '/')
		len++;

	fullpath = malloc(len);
	if (fullpath == NULL)
		return NULL;

	char *p = stpcpy(fullpath, "./");
	p = stpcpy(p, req->host);
	if (path[0] != '/')
		p = stpcpy(p, "/");
	stpcpy(p, path);

	return fullpath;
}

static void write_access_log(const char *method, const char *path,
                             const char *version, struct request *req,
                             enum MHD_Result ret) {
	char date[max_date_size];
	time_t now = time(NULL);
	if (now != -1) {
		struct tm *nowinfo = localtime(&now);
		strftime(date, max_date_size, "%d/%b/%Y:%T %z", nowinfo);
	} else {
		snprintf(date, max_date_size, "unknown");
	}

	const char *remote = req->remote;
	if (remote == NULL)
		remote = "-";

	struct param *refererp = NULL;
	HASH_FIND_STR(req->headers, "referer", refererp);
	const char *referer = refererp ? refererp->value : "";

	struct param *agentp = NULL;
	HASH_FIND_STR(req->headers, "user-agent", agentp);
	const char *user_agent = agentp ? agentp->value : "";

	fprintf(stdout, "%s %s - - [%s] \"%s %s %s\" %d %ld \"%s\" \"%s\"\n",
	        req->host,
	        remote,
	        date,
	        method,
	        path,
	        version,
	        req->resp->status,
	        req->resp->size,
	        referer,
	        user_agent);
}

static bool request_is_safe(const char *method) {
	return strcmp(method, "GET") == 0 ||
	       strcmp(method, "HEAD") == 0 ||
	       strcmp(method, "OPTIONS") == 0;
}

static enum MHD_Result init_request(void **con_cls, void *cls,
                                    struct MHD_Connection *conn, const char *path,
                                    const char *method, const char *version,
                                    const char *upload_data, size_t *upload_data_size) {
	struct server_info *srv_info = cls;

	struct request *req = malloc(sizeof *req);
	if (req == NULL) {
		DEBUG_PRINT("Failed allocating request: %s\n", strerror(errno));
		return MHD_NO;
	}

	req->is_safe = strcmp(method, "GET") == 0
	               || strcmp(method, "HEAD") == 0
	               || strcmp(method, "OPTIONS") == 0;
	req->version = version;
	req->method = method;
	req->url = curl_url();
	req->raw_path = path;
	req->dec_path = NULL;
	req->remote = NULL;
	req->postprocessor = NULL;
	req->headers = NULL;
	req->body_params = NULL;
	req->num_supported_encodings = 0;
	memset(req->supported_encodings, 0, sizeof(req->supported_encodings));
	req->res = NULL;
	req->resp = NULL;

	*con_cls = (void*)req;

	// Parse request headers
	MHD_get_connection_values(conn, MHD_HEADER_KIND, &parse_header, req);

	// Is this a localhost request?
	struct param *hostp = NULL;
	HASH_FIND_STR(req->headers, "host", hostp);
	if (hostp)
		req->host = hostp->value;

	// Parse scheme and remote client
	const union MHD_ConnectionInfo *info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_PROTOCOL|MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	req->scheme = "http";
	if (info != NULL) {
		if (info->protocol) {
			req->scheme = "https";
		}
		if (info->client_addr->sa_family == AF_INET) {
			struct sockaddr_in *in = (struct sockaddr_in *)info->client_addr;
			req->remote = strdup(inet_ntoa(in->sin_addr));
		}
	}

	// Parse the request path, constructing a full URL, an unescaped path and a
	// query string
	size_t urlen = strlen(req->scheme) + 3 + strlen(req->host) + strlen(req->raw_path);
	char url[urlen+1];
	snprintf(url, urlen+1, "%s://%s%s", req->scheme, req->host, req->raw_path);

	CURLUcode rc = curl_url_set(req->url, CURLUPART_URL, url, 0);
	if (rc != CURLE_OK) {
		fprintf(stderr, "Failed parsing request URL %s: %s\n", url, curl_url_strerror(rc));
		return MHD_NO;
	}

	MHD_get_connection_values(conn, MHD_GET_ARGUMENT_KIND, &build_qs, req);

	rc = curl_url_get(req->url, CURLUPART_PATH, &req->dec_path, CURLU_URLENCODE);
	if (rc != CURLE_OK) {
		req->dec_path = strdup(path);
	}

	// Locate the requested resource in the file system
	char *fullpath = get_fullpath(req, req->dec_path);

	if (fullpath == NULL) {
		DEBUG_PRINT("Full path is NULL\n");
		return MHD_NO;
	}

	DEBUG_PRINT("Full path is %s\n", fullpath);

	req->res = locate_resource_in_fs(req, fullpath, false);
	if (req->res == NULL) {
		DEBUG_PRINT("Resource is NULL\n");
		return MHD_NO;
	}

	DEBUG_PRINT("File path is %s\n", req->res->fullpath);

	if (req->res->type != PSGI && !request_is_safe(method)) {
		// TODO: need to returned Method Not Allowed
		return MHD_NO;
	}

	// Parse the Accept-Encoding header so we know which compression algorithms
	// the client supports
	parse_accept_encoding(req);

	if (method[0] == 'P') {
		struct param *ct = NULL;
		HASH_FIND_STR(req->headers, "content-type", ct);
		if (ct != NULL) {
			req->postprocessor = MHD_create_post_processor(
				conn, 65536, &iterate_post, (void *)&req);

			if (req->postprocessor == NULL) {
				DEBUG_PRINT("POST processor is NULL\n");
				return MHD_NO;
			}
		}
	}

	return MHD_YES;
}

enum MHD_Result handle_req(void *cls, struct MHD_Connection *conn, const char *path,
                           const char *method, const char *version,
                           const char *upload_data, size_t *upload_data_size,
                           void **con_cls) {
	struct server_info *srv_info = cls;

	if (*con_cls == NULL)
		return init_request(con_cls, cls, conn, path, method, version, upload_data, upload_data_size);

	struct request *req = *con_cls;
	int ret = MHD_NO;

	// If request is unsafe (i.e. not GET/HEAD/etc.) and has a POST processor,
	// execute it
	if (!req->is_safe && req->postprocessor != NULL && *upload_data_size != 0) {
		// upload not yet done
		if (MHD_post_process(req->postprocessor, upload_data, *upload_data_size) != MHD_YES) {
			DEBUG_PRINT("POST processing failed\n");
			return MHD_NO;
		}

		*upload_data_size = 0;

		return MHD_YES;
	}

	// If request is safe, try serving it from cache.
	if (req->is_safe) {
		ret = try_serving_from_cache(srv_info, conn, req);
		if (ret == MHD_YES)
			goto cleanup;
	}

	// Serving from cache failed, let's serve the file based on its type.
	switch (req->res->type) {
	case PSGI:
		ret = serve_psgi(conn, req);
		break;
	default:
		ret = serve_file(srv_info, conn, req);
	}

cleanup:
	write_access_log(method, path, version, req, ret);

	return ret;
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

	config_lookup_string(&config, "default_title", &srv_info->default_title);

	config_setting_t *ignore = config_lookup(&config, "ignore");
	if (ignore != NULL) {
		int count = config_setting_length(ignore);
		srv_info->ignore = malloc(sizeof(char *)*count);
		if (srv_info->ignore == NULL) {
			fprintf(stderr, "Failed allocating memory for ignore array: %s\n", strerror(errno));
			return 1;
		}

		for (int i = 0; i < count; i++)
			srv_info->ignore[i] = config_setting_get_string_elem(ignore, i);
	}

	config_destroy(&config);

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

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
	(void)_;
	keep_running = 0;
}

int main(int argc, char **argv, char **env) {
	signal(SIGINT, sig_handler);

	struct server_info srv_info;
	struct MHD_Daemon *daemon;

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

	rc = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (rc) {
		fprintf(stderr, "Failed initializing libcurl\n");
		goto cleanup;
	}

	srv_info.curl = curl_easy_init();
	if (srv_info.curl == NULL) {
		rc = 1;
		fprintf(stderr, "Failed initializing libcurl's easy interface\n");
		goto cleanup;
	}

	// Load configuration
	load_config(&srv_info);

	// Start the HTTP server
	unsigned int mhd_flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG;
	if (MHD_is_feature_supported(MHD_FEATURE_EPOLL))
		mhd_flags |= MHD_USE_EPOLL;
	else if (MHD_is_feature_supported(MHD_FEATURE_POLL))
		mhd_flags |= MHD_USE_POLL;
#ifdef DEBUG
	mhd_flags |= MHD_USE_DEBUG;
	long int thread_pool_size = 1;
#else
	long int thread_pool_size = sysconf(_SC_NPROCESSORS_ONLN);
#endif

	DEBUG_PRINT("Starting HTTP server...\n");

	daemon = MHD_start_daemon(
		mhd_flags, params.port_arg,
		NULL, NULL, &handle_req, &srv_info,
		MHD_OPTION_NOTIFY_COMPLETED, &request_completed, NULL,
		MHD_OPTION_CONNECTION_TIMEOUT, 1800, NULL,
		MHD_OPTION_PER_IP_CONNECTION_LIMIT, 10, NULL,
		MHD_OPTION_THREAD_POOL_SIZE, thread_pool_size, NULL,
		MHD_OPTION_END);
	if (daemon == NULL) {
		rc = 1;
		goto cleanup;
	}

	DEBUG_PRINT("Server is listening on 0.0.0.0:%d\n", params.port_arg);

	while (keep_running)
		(void)0;

cleanup:
	if (daemon != NULL) {
		fprintf(stderr, "Shutting down server\n");
		MHD_stop_daemon(daemon);
	}

	if (srv_info.curl != NULL)
		curl_easy_init();
	curl_global_cleanup();

	if (srv_info.magic_db != NULL)
		magic_close(srv_info.magic_db);

	destroy_perl();

	exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
}
