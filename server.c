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
#include "config.h"

#include <arpa/inet.h> // for inet_ntoa
#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <magic.h>
#include <microhttpd.h>
#include <netinet/in.h> // for sockaddr_in
#include <signal.h>     // for size_t, signal, SIGINT
#include <sqlite3.h>
#include <stdbool.h>    // for false, bool, true
#include <stdint.h>     // for uint64_t
#include <stdio.h>      // for NULL, fprintf, stderr, stdout
#include <stdlib.h>     // for free, malloc
#include <string.h>     // for strlen, strncmp, strcmp, strndup
#include <strings.h>    // for strcasecmp
#include <sys/socket.h> // for AF_INET, sockaddr
#include <time.h>       // for strftime, localtime, time

#include "database.h"
#include "library.h"
#include "server.h"

struct MHD_Connection;

struct server_info {
  magic_t magic_db;
};

static enum MHD_Result parse_header(void *cls, enum MHD_ValueKind kind,
                                    const char *key, const char *value) {
  struct connection_info *con_info = cls;

  if (strcasecmp(key, "Host") == 0) {
    if (con_info->host == NULL)
      con_info->host = value;
  } else if (strcasecmp(key, "Referer") == 0) {
    con_info->referer = value;
  } else if (strcasecmp(key, "User-Agent") == 0) {
    con_info->agent = value;
  } else if (strcasecmp(key, "X-Forwarded-Host") == 0) {
    con_info->host = value;
  } else if (strcasecmp(key, "X-Forwarded-Proto") == 0) {
    con_info->scheme = value;
  } else if (strcasecmp(key, "X-Forwarded-For") == 0) {
    con_info->remote = value;
  } else if (strcasecmp(key, "Content-Type") == 0) {
    if (strncmp(value, "application/x-www-form-urlencoded",
                strlen("application/x-www-form-urlencoded")) == 0) {
      con_info->content_type = CT_URLENCODED;
    } else if (strncmp(value, "multipart/form-data",
                       strlen("multipart/form-data")) == 0) {
      con_info->content_type = CT_MULTIPART;
    } else if (strncmp(value, "application/json", strlen("application/json")) ==
               0) {
      con_info->content_type = CT_JSON;
    }
  }

  return MHD_YES;
}

static enum MHD_Result push_header(void *cls, enum MHD_ValueKind kind,
                                   const char *key, const char *value) {
  struct connection_info *con_info = cls;
  pushtableliteral(con_info->L, key, value);
  return MHD_YES;
}

static enum MHD_Result collect_param(void *cls, enum MHD_ValueKind kind,
                                     const char *key, const char *value) {
  lua_State *L = (lua_State *)cls;
  lua_pushstring(L, key);
  int ct = lua_gettable(L, -2);

  if (ct == LUA_TTABLE) {
    // push to existing array
    lua_pushinteger(L, luaL_len(L, -1) + 1);
    lua_pushstring(L, value);
    lua_settable(L, -3);
    lua_pushstring(L, key);
    lua_insert(L, -2);
    lua_settable(L, -3);
  } else if (ct == LUA_TSTRING) {
    // turn to an array
    const char *existing = lua_tostring(L, -1);
    lua_pop(L, 1);
    lua_pushstring(L, key);
    lua_newtable(L);
    lua_pushstring(L, existing);
    lua_seti(L, -2, 1);
    lua_pushstring(L, value);
    lua_seti(L, -2, 2);
    lua_settable(L, -3);
  } else {
    // push new value
    lua_pop(L, 1);
    pushtableliteral(L, key, value);
  }

  return MHD_YES;
}

static void build_context(struct MHD_Connection *conn,
                          struct connection_info *con_info) {
  struct resource *resource = con_info->resource;

  lua_State *L = con_info->L;

  lua_newtable(L);

  lua_pushliteral(L, "headers");
  lua_newtable(L);
  MHD_get_connection_values(conn, MHD_HEADER_KIND, &push_header, con_info);
  lua_settable(L, -3);

  lua_pushliteral(L, "params");
  lua_newtable(L);
  MHD_get_connection_values(conn, MHD_GET_ARGUMENT_KIND, &collect_param, L);
  lua_settable(L, -3);

  lua_pushstring(L, "baseurl");
  lua_pushfstring(L, "%s://%s", con_info->scheme, con_info->host);
  lua_settable(L, -3);

  pushtableliteral(L, "scheme", con_info->scheme);
  pushtableliteral(L, "host", con_info->host);
  pushtableliteral(L, "method", con_info->method);
  pushtableliteral(L, "path", con_info->path);
  pushtableliteral(L, "slug", resource->slug);
  pushtablestring(L, "srcpath", resource->srcpath);
  pushtableliteral(L, "name", resource->name);
  pushtablelstring(L, "content", resource->content, resource->size);
  if (resource->ctime > 0) {
    char *ctime = parse_time(resource->ctime);
    pushtablestring(L, "ctime", ctime);
    free(ctime);
  }
  if (resource->mtime > 0) {
    char *mtime = parse_time(resource->mtime);
    pushtablestring(L, "mtime", mtime);
    free(mtime);
  }
  pushtableint(L, "status", con_info->status);

  lua_pushliteral(L, "tags");
  lua_newtable(L);
  if (resource->tags) {
    for (int i = 0; resource->tags[i] != NULL; i++) {
      lua_pushinteger(L, i + 1);
      lua_pushstring(L, resource->tags[i]);
      lua_settable(L, -3);
    }
  }
  lua_settable(L, -3);
}

static int prepare_lua_resource(struct server_info *srv_info,
                                struct connection_info *con_info) {
  int rc = luaL_dostring(con_info->L, con_info->resource->content);
  if (rc != LUA_OK) {
    fprintf(stderr, "Failed evaluating Lua code: %s\n",
            lua_tostring(con_info->L, -1));
    lua_pop(con_info->L, 1);
    return rc;
  }
  // stack: [context, resource_lua]

  lua_insert(con_info->L, 1);
  // stack: [resource_lua, context]

  if (lua_getglobal(con_info->L, "render") != LUA_TFUNCTION) {
    fprintf(stderr, "Failed getting resource's render function, it is %s\n",
            lua_typename(con_info->L, lua_type(con_info->L, -1)));
    return 1;
  }
  lua_insert(con_info->L, 2);
  // stack: [resource_lua, render, context]

  lua_newtable(con_info->L);
  pushtableclosure(con_info->L, "list_resources", list_resources, 0);
  pushtableclosure(con_info->L, "query_db", query_db, 1, con_info->db);
  pushtableclosure(con_info->L, "execute_cmd", execute_cmd, 0);
  pushtableclosure(con_info->L, "render_tmpl", render_tmpl, 1, con_info);
  pushtableclosure(con_info->L, "http_request", http_request, 0);
  pushtableclosure(con_info->L, "base64enc", base64enc, 0);
  pushtableclosure(con_info->L, "base64dec", base64dec, 0);
  lua_insert(con_info->L, 3);
  // stack: [resource_lua, render, sheepwool_lib, context]

  return 0;
}

static int render_resource(struct server_info *srv_info,
                           struct MHD_Connection *conn,
                           struct connection_info *con_info) {
  if (strcmp(con_info->resource->mime, "text/html") == 0) {
    lua_pushstring(con_info->L, con_info->resource->tmpl);
    lua_insert(con_info->L, 1);
    lua_pushlightuserdata(con_info->L, con_info);
    render_tmpl(con_info->L);
    size_t size = 0;
    const char *content = lua_tolstring(con_info->L, -1, &size);
    con_info->resource->content = strndup(content, size);
    con_info->resource->size = size;
  } else if (strcmp(con_info->resource->mime, "text/x-lua") == 0) {
    int rc = prepare_lua_resource(srv_info, con_info);
    if (rc)
      return rc;

    if (lua_gettop(con_info->L) == 3)
      lua_newtable(con_info->L);

    // stack: [con_info->resource_lua, render, sheepwool, context]
    if (lua_gettop(con_info->L) == 5) {
      // assume value at top of stack is an error, push it into context
      lua_pushliteral(con_info->L, "error");
      lua_insert(con_info->L, 5);
      lua_settable(con_info->L, 4);
    }

    rc = lua_pcall(con_info->L, 2, 2, 0);
    if (rc != LUA_OK) {
      fprintf(stderr, "Failed rendering Lua resource: %s (code: %d)\n",
              lua_tostring(con_info->L, -1), rc);
      return rc;
    }
    // stack: [con_info->resource_lua, mime, content]

    con_info->resource->mime = lua_tostring(con_info->L, -2);
    size_t size = 0;
    const char *content = lua_tolstring(con_info->L, -1, &size);
    con_info->resource->content = strndup(content, size);
    con_info->resource->size = size;
  }

  return 0;
}

static enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                                    const char *key, const char *filename,
                                    const char *content_type,
                                    const char *transfer_encoding,
                                    const char *data, uint64_t off,
                                    size_t size) {
  if (kind == MHD_POSTDATA_KIND) {
    struct connection_info *con_info = coninfo_cls;
    lua_State *L = con_info->L;
    lua_pushliteral(L, "params");
    lua_gettable(L, -2);
    collect_param(L, kind, key, data);
    lua_pop(L, 1);
  }

  return MHD_YES;
}

static void request_completed(void *cls, struct MHD_Connection *connection,
                              void **con_cls,
                              enum MHD_RequestTerminationCode toe) {
  struct connection_info *con_info = *con_cls;

  if (con_info == NULL)
    return;

  if (con_info->postprocessor != NULL)
    MHD_destroy_post_processor(con_info->postprocessor);

  lua_close(con_info->L);
  free_resource(con_info->resource);
  if (con_info->db != NULL)
    sqlite_disconnect(con_info->db);
  free(con_info);
  *con_cls = NULL;
}

static enum MHD_Result handle_req(void *cls, struct MHD_Connection *conn,
                                  const char *path, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls) {
  struct server_info *srv_info = cls;

  if (*con_cls == NULL) {
    fprintf(stderr, "New %s request for %s using %s\n", method, path, version);

    struct connection_info *con_info = malloc(sizeof(struct connection_info));
    if (con_info == NULL)
      return MHD_NO;

    con_info->magic_db = srv_info->magic_db;
    con_info->is_localhost = false;
    con_info->resource = NULL;
    con_info->host = NULL;
    con_info->remote = NULL;
    con_info->referer = "-";
    con_info->agent = "";
    con_info->scheme = "http";
    con_info->content_type = CT_OTHER;
    con_info->postprocessor = NULL;
    con_info->method = method;
    con_info->path = path;
    con_info->status = 0;
    con_info->parse_body = false;

    con_info->L = luaL_newstate();
    luaL_openlibs(con_info->L);

    MHD_get_connection_values(conn, MHD_HEADER_KIND, &parse_header, con_info);

    if (con_info->host == NULL ||
        str_starts_with(con_info->host, "localhost") ||
        str_starts_with(con_info->host, "0.0.0.0") ||
        str_starts_with(con_info->host, "127.0.0.1"))
      con_info->is_localhost = true;

    char *dbpath =
        get_abspath(con_info->host, con_info->is_localhost, "/db.sqlite3");
    if (dbpath == NULL)
      return MHD_NO;

    int rc = sqlite_connect(&con_info->db, dbpath, false);
    if (rc)
      return MHD_NO;

    const union MHD_ConnectionInfo *ci =
        MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci != NULL && ci->client_addr->sa_family == AF_INET) {
      struct sockaddr_in *in = (struct sockaddr_in *)ci->client_addr;
      con_info->remote = inet_ntoa(in->sin_addr);
    }

    con_info->resource = load_resource(con_info, path);

    if (con_info->resource == NULL) {
      con_info->status = MHD_HTTP_NOT_FOUND;
    } else {
      build_context(conn, con_info);

      if ((strcasecmp(con_info->method, MHD_HTTP_METHOD_POST) == 0 ||
           strcasecmp(con_info->method, MHD_HTTP_METHOD_PUT) == 0 ||
           strcasecmp(con_info->method, MHD_HTTP_METHOD_PATCH) == 0) &&
          (con_info->content_type == CT_URLENCODED ||
           con_info->content_type == CT_MULTIPART)) {
        con_info->parse_body = true;
      }

      if (con_info->parse_body) {
        con_info->postprocessor = MHD_create_post_processor(
            conn, 512, &iterate_post, (void *)con_info);

        if (con_info->postprocessor == NULL) {
          free(con_info);
          return MHD_NO;
        }
      }
    }

    *con_cls = (void *)con_info;

    return MHD_YES;
  }

  struct connection_info *con_info = *con_cls;

  if (con_info->parse_body) {
    if (*upload_data_size != 0) {
      // upload not yet done
      if (con_info->status != 0) {
        // we already know the answer, skip rest of upload
        *upload_data_size = 0;
        return MHD_YES;
      }

      if (MHD_post_process(con_info->postprocessor, upload_data,
                           *upload_data_size) != MHD_YES) {
        fprintf(stderr, "Failed post processing\n");
        con_info->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
      }

      *upload_data_size = 0;

      return MHD_YES;
    }
  }

  if (con_info->status == 0) {
    int rc = render_resource(srv_info, conn, con_info);
    if (rc)
      con_info->status = 500;
  }

  if (con_info->status) {
    if (con_info->resource)
      free_resource(con_info->resource);
    con_info->resource = load_resource(con_info, "/error");
    if (con_info->resource) {
      int rc = render_resource(srv_info, conn, con_info);
      if (rc) {
        free_resource(con_info->resource);
        con_info->resource =
            error_resource(path, MHD_HTTP_INTERNAL_SERVER_ERROR);
      }
    } else {
      con_info->resource = error_resource(path, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
  }

  con_info->status =
      con_info->resource->status ? con_info->resource->status : MHD_HTTP_OK;

  struct MHD_Response *response = MHD_create_response_from_buffer(
      con_info->resource->size, (void *)con_info->resource->content,
      MHD_RESPMEM_MUST_COPY);

  MHD_add_response_header(response, "Content-Type", con_info->resource->mime);

  if (con_info->resource->moved_to != NULL)
    MHD_add_response_header(response, "Location", con_info->resource->moved_to);

  enum MHD_Result ret = MHD_queue_response(conn, con_info->status, response);

  size_t max_date_size = strlen("18/Sep/2011:19:18:28 -0400") + 6;
  char *date = malloc(max_date_size);
  time_t now = time(NULL);
  if (now != -1) {
    struct tm *nowinfo = localtime(&now);
    strftime(date, max_date_size, "%d/%b/%Y:%T %z", nowinfo);
  } else {
    snprintf(date, max_date_size, "unknown");
  }
  fprintf(stdout, "%s %s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
          con_info->host, con_info->remote, date, method, path, version,
          con_info->status, con_info->resource->size, con_info->referer,
          con_info->agent);
  free(date);

  MHD_destroy_response(response);

  return ret;
}

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
  (void)_;
  keep_running = 0;
}

int serve(unsigned int port) {
  signal(SIGINT, sig_handler);

  struct server_info *srv_info = malloc(sizeof(struct server_info));
  srv_info->magic_db = magic_open(MAGIC_MIME_TYPE);
  if (srv_info->magic_db == NULL) {
    fprintf(stderr, "Failed opening libmagic cookie: %s\n", strerror(errno));
    goto cleanup;
  }

  if (magic_load(srv_info->magic_db, NULL) != 0) {
    fprintf(stderr, "Failed loading libmagic DB: %s\n",
            magic_error(srv_info->magic_db));
    goto cleanup;
  }

  int rc = 0;

  struct MHD_Daemon *daemon = MHD_start_daemon(
      MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, port,
      NULL, NULL, &handle_req, srv_info, MHD_OPTION_NOTIFY_COMPLETED,
      &request_completed, NULL, MHD_OPTION_END);
  if (daemon == NULL) {
    rc = 1;
    goto cleanup;
  }

  fprintf(stderr, "Server is listening on 0.0.0.0:%d\n", port);

  while (keep_running)
    (void)0;

  fprintf(stderr, "Shutting down server\n");
  MHD_stop_daemon(daemon);

cleanup:
  if (srv_info->magic_db != NULL)
    magic_close(srv_info->magic_db);
  free(srv_info);

  return rc;
}
