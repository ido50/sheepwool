/*	$Id$ */
/*
 * Copyright (c) 2022 Ido Perlmuter <sheepwool@ido50.net>
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

#include <arpa/inet.h> // for inet_ntoa
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libgen.h>  //for basename
#include <magic.h>
#include <microhttpd.h>
#include <netinet/in.h> // for sockaddr_in
#include <regex.h>
#include <signal.h>
#include <stdbool.h>    // for false, bool, true
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    // for strcasecmp
#include <sys/socket.h> // for AF_INET, sockaddr
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>       // for strftime, localtime, time
#include <unistd.h>
#include <EXTERN.h>
#include <perl.h>

#include "cmdline.h"
#include "hash.h"
#include "list.h"
#include "str-utils.h"

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args ...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args ...)    /* Don't do anything in release builds */
#endif

extern int pledge(const char *promises, const char *execpromises);
extern int unveil(const char *path, const char *permissions);

static size_t max_date_size = strlen("18/Sep/2011:19:18:28 -0400") + 6;

struct server_info {
	magic_t magic_db;
};

enum param_type {
	STRING = 1,
	ARRAY = 2
};

struct body_param {
	enum param_type type;
	const char *string_value;
	list_t *list_value;
};

struct resource {
	char *fullpath;
	off_t size;
};

struct request {
	bool is_localhost;
	struct MHD_PostProcessor *postprocessor;
	hash_t *headers;
	hash_t *body_params;
	char *remote;
	int status;
	struct resource *res;
};

void request_completed(void *cls, struct MHD_Connection *connection,
                       void **con_cls, enum MHD_RequestTerminationCode toe) {
	if (*con_cls == NULL)
		return;

	struct request *req = *con_cls;

	if (req->remote != NULL) {
		free(req->remote);
	}

	if (req->headers != NULL)
		hash_free(req->headers);

	if (req->res == NULL)
		return;

	if (req->postprocessor != NULL)
		MHD_destroy_post_processor(req->postprocessor);

	if (req->body_params != NULL)
		hash_free(req->body_params);

	free(req->res->fullpath);
	free(req->res);
	free(req);

	*con_cls = NULL;
}

/*static int parse_html(struct resource *res, char *abspath) {*/
/*char *line = NULL;*/
/*size_t len = 0;*/
/*ssize_t read;*/
/*regex_t regex;*/
/*regmatch_t matches[3];*/
/*long mismatch_position = -1;*/

/*// Compile the regular expression*/
/*if (regcomp(&regex, "<!--\\s*KEY:\\s*(.+)\\s*VALUE:\\s*(.+)\\s*-->", REG_EXTENDED)) {*/
/*fprintf(stderr, "Could not compile regex\n");*/
/*return 1;*/
/*}*/

/*res->mime = "text/html";*/

/*while ((read = getline(&line, &len, res->fh)) != -1) {*/
/*if (!regexec(&regex, line, 3, matches, 0)) {*/
/*char key[matches[1].rm_eo - matches[1].rm_so + 1];*/
/*char value[matches[2].rm_eo - matches[2].rm_so + 1];*/

/*strncpy(key, line + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);*/
/*key[matches[1].rm_eo - matches[1].rm_so] = '\0';*/

/*strncpy(value, line + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);*/
/*value[matches[2].rm_eo - matches[2].rm_so] = '\0';*/

/*printf("Found KEY: %s, VALUE: %s\n", key, value);*/

/*if (strcmp(key, "name") == 0) {*/
/*if (res->name != NULL)*/
/*free(res->name);*/
/*res->name = strdup(value);*/
/*} else if (strcmp(key, "template") == 0) {*/
/*res->tmpl = strdup(value);*/
/*} else if (strcmp(key, "status") == 0) {*/
/*if (strcmp(value, "gone") == 0) {*/
/*res->status = MHD_HTTP_GONE;*/
/*} else if (strcmp(value, "moved") == 0) {*/
/*res->status = MHD_HTTP_MOVED_PERMANENTLY;*/
/*} else {*/
/*res->status = MHD_HTTP_OK;*/
/*}*/
/*} else if (strcmp(key, "tags") == 0) {*/
/*char *tags = strdup(value);*/
/*int i = 0;*/
/*char *tag = strtok(tags, ", ");*/
/*while (tag) {*/
/*// we are allocating enough memory for one tag (or the number of tags*/
/*// we have) plus one NULL pointer (sentinel)*/
/*if (i > 0)*/
/*res->tags = realloc(res->tags, sizeof(char *) * (i + 2));*/
/*else*/
/*res->tags = malloc(sizeof(char *) * 2);*/
/*res->tags[i] = tag;*/
/*tag = strtok(NULL, ", ");*/
/*i++;*/
/*}*/
/*res->tags[i] = NULL;*/
/*} else if (strcmp(key, "ctime") == 0) {*/
/*res->ctime = strdup(value);*/
/*} else if (strcmp(key, "mtime") == 0) {*/
/*res->mtime = strdup(value);*/
/*}*/
/*} else {*/
/*mismatch_position = ftell(res->fh);*/
/*break;*/
/*}*/
/*}*/

/*free(line);*/
/*regfree(&regex);*/

/*if (mismatch_position != -1) {*/
/*// Allocate memory for the remainder of the file*/
/*long remainder_size = res->size - mismatch_position;*/
/*res->size -= mismatch_position;*/
/*res->content = malloc(remainder_size + 1);*/
/*fread(res->content, 1, remainder_size, res->fh);*/
/*res->content[remainder_size] = '\0';*/
/*}*/

/*return 0;*/
/*}*/

static enum MHD_Result serve_resource(struct server_info *srv_info,
                                      struct MHD_Connection *conn,
                                      struct request *req) {
	int fd = open(req->res->fullpath, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed opening file %s: %s\n", req->res->fullpath, strerror(errno));
		return MHD_NO;
	}

	struct MHD_Response *response = MHD_create_response_from_fd(req->res->size, fd);

	const char *content_type = magic_file(srv_info->magic_db, req->res->fullpath);
	if (content_type == NULL)
		content_type = "text/plain";

	MHD_add_response_header(response, "Content-Type", content_type);

	enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, response);

	MHD_destroy_response(response);

	return ret;
}

static enum MHD_Result collect_param(void *coninfo_cls, enum MHD_ValueKind kind,
                                     const char *key, const char *value) {
	struct request *req = coninfo_cls;

	struct body_param *param = hash_get(req->body_params, key);

	if (param == NULL) {
		// new string parameter
		struct body_param param = {
			.string_value = value,
			.type = STRING,
		};
		hash_set(req->body_params, key, &param);
		return MHD_YES;
	}

	if (param->type == ARRAY) {
		// Push to an existing array
		list_rpush(param->list_value, list_node_new((void*)value));
	} else {
		// Turn existing string into an array and push new value
		param->type = ARRAY;
		param->list_value = list_new();
		list_rpush(param->list_value, list_node_new((void*)param->string_value));
		list_rpush(param->list_value, list_node_new((void*)value));
	}

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
	hash_t *headers = cls;
	hash_set(headers, case_lower((char*)key), (void*)value);
	return MHD_YES;
}

static enum MHD_Result parse_request(struct MHD_Connection *conn,
                                     const char *path, const char *method,
                                     const char *upload_data,
                                     size_t *upload_data_size,
                                     struct request *req) {
	if (method[0] == 'P') {
		const char *content_type = hash_get(req->headers, "content-type");
		if (content_type != NULL && (
			    str_starts_with(content_type, "application/x-www-form-urlencoded") ||
			    str_starts_with(content_type, "multipart/form-data")
			    )) {
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

static struct resource *locate_resource(struct request *req, char *fullpath, bool exact) {
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
		fullpath = realloc(fullpath, strlen(fullpath) + 4);
		if (fullpath == NULL) {
			fprintf(stderr, "Failed reallocing fullpath: %s\n", strerror(errno));
			abort();
		}
		strcat(fullpath, ".html");
		return locate_resource(req, fullpath, true);
	}

	if (S_ISDIR(fstat.st_mode)) {
		// This is a directory, look for an index.html file in it
		fullpath = realloc(fullpath, strlen(fullpath) + 11);
		if (fullpath == NULL) {
			fprintf(stderr, "Failed reallocing fullpath: %s\n", strerror(errno));
			return NULL;
		}
		if (str_ends_with(fullpath, "/"))
			strcat(fullpath, "index.html");
		else
			strcat(fullpath, "/index.html");
		return locate_resource(req, fullpath, true);
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
		res->size = fstat.st_size;
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

	if (req->is_localhost) {
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
	const char *host = hash_get(req->headers, "host");
	len += strlen(host);

	// we need a heading slash when we have a host
	if (path[0] != '/')
		len++;

	fullpath = malloc(len);
	if (fullpath == NULL)
		return NULL;

	char *p = stpcpy(fullpath, "./");
	p = stpcpy(p, host);
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

	const char *referer = hash_get(req->headers, "referer");
	if (referer == NULL)
		referer = "";

	const char *user_agent = hash_get(req->headers, "user-agent");
	if (user_agent == NULL)
		user_agent = "";

	fprintf(stdout, "%s %s - - [%s] \"%s %s %s\" %d %ld \"%s\" \"%s\"\n",
	        (const char*)hash_get(req->headers, "host"),
	        remote,
	        date,
	        method,
	        path,
	        version,
	        ret == MHD_YES ? MHD_HTTP_OK : MHD_HTTP_INTERNAL_SERVER_ERROR,
	        req->res->size,
	        referer,
	        user_agent);
}

static enum MHD_Result init_request(void *cls, struct MHD_Connection *conn, const char *path,
                                    const char *method, const char *version,
                                    const char *upload_data, size_t *upload_data_size,
                                    struct request *req) {

	// Parse request headers
	MHD_get_connection_values(conn, MHD_HEADER_KIND, &parse_header, req->headers);

	// Is this a localhost request?
	const char *host = hash_get(req->headers, "host");
	if (host == NULL ||
	    str_starts_with(host, "localhost") ||
	    str_starts_with(host, "0.0.0.0") ||
	    str_starts_with(host, "127.0.0.1"))
		req->is_localhost = true;

	const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	if (ci != NULL && ci->client_addr->sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)ci->client_addr;
		req->remote = strdup(inet_ntoa(in->sin_addr));
	}

	char *fullpath = get_fullpath(req, path);
	if (fullpath == NULL) {
		DEBUG_PRINT("Full path is NULL\n");
		return MHD_NO;
	}

	DEBUG_PRINT("Full path is %s\n", fullpath);

	req->res = locate_resource(req, fullpath, false);
	if (req->res == NULL) {
		DEBUG_PRINT("Resource is NULL\n");
		return MHD_NO;
	}

	DEBUG_PRINT("Final path is %s\n", req->res->fullpath);

	return parse_request(conn, path, method, upload_data, upload_data_size, req);
}

enum MHD_Result handle_req(void *cls, struct MHD_Connection *conn, const char *path,
                           const char *method, const char *version,
                           const char *upload_data, size_t *upload_data_size,
                           void **con_cls) {
	if (*con_cls == NULL) {
		struct request *req = malloc(sizeof *req);
		if (req == NULL) {
			DEBUG_PRINT("Request is NULL\n");
			return MHD_NO;
		}

		req->status = 0;
		req->res = NULL;
		req->is_localhost = false;
		req->remote = NULL;
		req->postprocessor = NULL;
		req->headers = hash_new();
		req->body_params = hash_new();

		*con_cls = (void*)req;

		return init_request(cls, conn, path, method, version, upload_data, upload_data_size, req);
	}

	struct server_info *srv_info = cls;
	struct request *req = *con_cls;

	if (req->postprocessor != NULL && *upload_data_size != 0) {
		// upload not yet done
		if (MHD_post_process(req->postprocessor, upload_data, *upload_data_size) != MHD_YES) {
			DEBUG_PRINT("POST processing failed\n");
			return MHD_NO;
		}

		*upload_data_size = 0;

		return MHD_YES;
	}

	int ret = serve_resource(srv_info, conn, req);

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

		rc = unveil("/etc/ssl/cert.pem", "r");
		if (rc == -1) {
			fprintf(stderr, "Failed unveiling certificates\n");
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
	PERL_SYS_INIT3(&argc, &argv, &env);

	signal(SIGINT, sig_handler);

	struct server_info srv_info;
	struct MHD_Daemon *daemon;

	// Parse command line arguments
	struct gengetopt_args_info params;
	int rc = cmdline_parser(argc, argv, &params);
	if ( rc != 0 )
		goto cleanup;

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

	// Start the HTTP server
	unsigned int mhd_flags = MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG;
	if (HAVE_EPOLL)
		mhd_flags |= MHD_USE_EPOLL;
	else if (HAVE_POLL)
		mhd_flags |= MHD_USE_POLL;
#ifdef DEBUG
	mhd_flags |= MHD_USE_DEBUG;
	long int thread_pool_size = 1;
#else
	long int thread_pool_size = sysconf(_SC_NPROCESSORS_ONLN);
#endif

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

	if (srv_info.magic_db != NULL)
		magic_close(srv_info.magic_db);

	PERL_SYS_TERM();

	exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
}
