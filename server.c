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

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <microhttpd.h>
#include <sqlite3.h>

#include "database.h"
#include "lua_registry.h"
#include "server.h"

struct MHD_Connection;

const struct luaL_Reg lua_lib[] = {{"query_db", query_db},
                                   {"execute_cmd", execute_cmd},
                                   {"render_tmpl", render_tmpl},
                                   {"http_request", http_request},
                                   {"base64enc", base64enc},
                                   {"base64dec", base64dec},
                                   {NULL, NULL}};

enum ContentType {
  CT_OTHER = 0,
  CT_URLENCODED = 1,
  CT_MULTIPART = 2,
  CT_JSON = 3
};

struct connection_info {
  enum ContentType content_type;
  lua_State *L;
  const char *scheme;
  const char *host;
  const char *method;
  const char *path;
  bool parse_body;
  struct MHD_PostProcessor *postprocessor;
  struct resource *resource;
  unsigned int status;
};

static enum MHD_Result collect_header(void *cls, enum MHD_ValueKind kind,
                                      const char *key, const char *value) {
  struct connection_info *con_info = cls;

  if (strcasecmp(key, "Host") == 0) {
    if (con_info->host == NULL)
      con_info->host = value;
  } else if (strcasecmp(key, "X-Forwarded-Host") == 0) {
    con_info->host = value;
  } else if (strcasecmp(key, "X-Forwarded-Proto") == 0) {
    con_info->scheme = value;
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
  MHD_get_connection_values(conn, MHD_HEADER_KIND, &collect_header, con_info);
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
  pushtablestring(L, "slug", resource->slug);
  pushtablestring(L, "srcpath", resource->srcpath);
  pushtablestring(L, "name", resource->name);
  pushtablelstring(L, "content", resource->content, resource->size);
  pushtablestring(L, "ctime", resource->ctime);
  pushtablestring(L, "mtime", resource->mtime);
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

static int prepare_lua_resource(lua_State *L, sqlite3 *db,
                                struct resource *res) {
  char lua_code[res->size + 1];
  memcpy(lua_code, res->content, sizeof(lua_code));
  lua_code[res->size] = '\0';

  int rc = luaL_dostring(L, lua_code);
  if (rc != LUA_OK) {
    syslog(LOG_ERR, "Failed evaluating Lua code: %s", lua_tostring(L, -1));
    return rc;
  }
  // stack: [context, resource_lua]

  lua_insert(L, 1);
  // stack: [resource_lua, context]

  if (lua_getglobal(L, "render") != LUA_TFUNCTION) {
    syslog(LOG_ERR, "Failed getting resource's render function, it is %s",
           lua_typename(L, lua_type(L, -1)));
    return 1;
  }
  lua_insert(L, 2);
  // stack: [resource_lua, render, context]

  luaL_newlib(L, lua_lib);
  lua_insert(L, 3);
  // stack: [resource_lua, render, sheepwool, context]

  lua_pushlightuserdata(L, db);
  lua_insert(L, 4);
  // stack: [resource_lua, render, sheepwool, db, context]

  return 0;
}

static int render_resource(sqlite3 *db, struct MHD_Connection *conn,
                           struct connection_info *con_info) {
  if (strcmp(con_info->resource->mime, "text/html") == 0 &&
      con_info->resource->tmpl != NULL) {
    lua_pushlightuserdata(con_info->L, db);
    lua_insert(con_info->L, 1);
    lua_pushstring(con_info->L, con_info->resource->tmpl);
    lua_insert(con_info->L, 2);
    render_tmpl(con_info->L);
    size_t size = 0;
    con_info->resource->content =
        sqlite3_mprintf("%s", lua_tolstring(con_info->L, -1, &size));
    con_info->resource->size = size;
  } else if (strcmp(con_info->resource->mime, "text/x-lua") == 0) {
    int rc = prepare_lua_resource(con_info->L, db, con_info->resource);
    if (rc)
      return rc;
    //
    // stack: [con_info->resource_lua, render, sheepwool, db, context]
    rc = lua_pcall(con_info->L, 3, 2, 0);
    if (rc != LUA_OK) {
      syslog(LOG_ERR, "Failed rendering Lua con_info->resource: %s (code: %d)",
             lua_tostring(con_info->L, -1), rc);
      return rc;
    }
    // stack: [con_info->resource_lua, mime, content]

    con_info->resource->mime =
        sqlite3_mprintf("%s", lua_tostring(con_info->L, -2));
    size_t size = 0;
    con_info->resource->content =
        sqlite3_mprintf("%s", lua_tolstring(con_info->L, -1, &size));
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
  free(con_info->resource);
  free(con_info);
  *con_cls = NULL;
}

static enum MHD_Result handle_req(void *cls, struct MHD_Connection *conn,
                                  const char *path, const char *method,
                                  const char *version, const char *upload_data,
                                  size_t *upload_data_size, void **con_cls) {
  sqlite3 *db = cls;

  if (*con_cls == NULL) {
    syslog(LOG_DEBUG, "New %s request for %s using %s\n", method, path,
           version);

    struct connection_info *con_info = malloc(sizeof(struct connection_info));
    if (con_info == NULL)
      return MHD_NO;

    con_info->resource = malloc(sizeof(struct resource));
    if (con_info->resource == NULL)
      return MHD_NO;

    con_info->host = NULL;
    con_info->scheme = "http";
    con_info->content_type = CT_OTHER;
    con_info->postprocessor = NULL;
    con_info->method = method;
    con_info->path = path;
    con_info->status = 0;
    con_info->parse_body = false;
    con_info->L = luaL_newstate();
    luaL_openlibs(con_info->L);

    int rc = load_resource(db, con_info->resource, path);

    if (rc == SQLITE_OK) {
      if (con_info->resource->status == GONE) {
        con_info->status = MHD_HTTP_GONE;
      } else if (con_info->resource->status == MOVED) {
        con_info->status = MHD_HTTP_MOVED_PERMANENTLY;
      }

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
    } else {
      if (rc == SQLITE_NOTFOUND) {
        con_info->status = MHD_HTTP_NOT_FOUND;
      } else {
        syslog(LOG_ERR, "Failed loading resource %s: %s", path,
               sqlite3_errstr(rc));
        con_info->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
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
                           *upload_data_size) != MHD_YES)
        con_info->status = MHD_HTTP_INTERNAL_SERVER_ERROR;

      *upload_data_size = 0;

      return MHD_YES;
    }
  }

  if (con_info->status == 0)
    con_info->status = MHD_HTTP_OK;

  int rc = con_info->status >= 400
               ? load_resource(db, con_info->resource, "/error") ||
                     render_resource(db, conn, con_info)
               : render_resource(db, conn, con_info);

  if (rc != SQLITE_OK) {
    con_info->resource->mime = sqlite3_mprintf("text/plain");
    con_info->resource->content = sqlite3_mprintf("Error %d", con_info->status);
    con_info->resource->size = strlen(con_info->resource->content);
  }

  struct MHD_Response *response = MHD_create_response_from_buffer(
      con_info->resource->size, (void *)con_info->resource->content,
      MHD_RESPMEM_MUST_COPY);

  MHD_add_response_header(response, "Content-Type", con_info->resource->mime);

  if (con_info->resource->moved_to != NULL)
    MHD_add_response_header(response, "Location", con_info->resource->moved_to);

  enum MHD_Result ret = MHD_queue_response(conn, con_info->status, response);

  MHD_destroy_response(response);

  return ret;
}

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
    (void)_;
    keep_running = 0;
}

int serve(sqlite3 *db, unsigned int port, char *logpath) {
  signal(SIGINT, sig_handler);

  struct MHD_Daemon *daemon = MHD_start_daemon(
      MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, port,
      NULL, NULL, &handle_req, db, MHD_OPTION_NOTIFY_COMPLETED,
      &request_completed, NULL, MHD_OPTION_END);
  if (daemon == NULL)
    return 1;

  syslog(LOG_INFO, "Server is listening on 0.0.0.0:%d", port);

  while (keep_running)
    (void)0;

  syslog(LOG_INFO, "Shutting down server");
  MHD_stop_daemon(daemon);

  return 0;
}
