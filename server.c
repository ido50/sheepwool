#include "config.h"

#include <h2o.h>
#include <h2o/http1.h>
#include <h2o/http2.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <netinet/in.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <uv.h>

#include "database.h"
#include "lua_registry.h"
#include "server.h"

const struct luaL_Reg lua_lib[] = {{"query", lua_query},
                                   {"execute", lua_execute},
                                   {"render", lua_render},
                                   {"post", lua_post_request},
                                   {"base64_encode", lua_base64_encode},
                                   {"base64_decode", lua_base64_decode},
                                   {NULL, NULL}};

static sqlite3 *db;
static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;

static int render_lua_resource(sqlite3 *db, struct resource *res,
                               h2o_headers_t headers, char *host, char *method,
                               const char *scheme, char *path, char *query,
                               const int status) {
  syslog(LOG_DEBUG, "Rendering Lua resource %s with status %d", res->slug,
         status);

  int rc = 0;

  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  char *lua_code = malloc(res->size + 1);
  strlcpy(lua_code, res->content, res->size);
  lua_code[res->size] = '\0';

  syslog(LOG_DEBUG, "Evaluating Lua code");

  rc = luaL_dostring(L, lua_code);
  if (rc != LUA_OK) {
    syslog(LOG_ERR, "Failed evaluating Lua code: %s", lua_tostring(L, -1));
    goto cleanup;
  }

  syslog(LOG_DEBUG, "Getting render function");

  if (lua_getglobal(L, "render") != LUA_TFUNCTION) {
    syslog(LOG_ERR, "Failed getting resource's render function, it is %s",
           lua_typename(L, lua_type(L, -1)));
    rc = 1;
    goto cleanup;
  }
  // stack: [resource_lua, render]

  luaL_newlib(L, lua_lib);
  // stack: [resource_lua, render, sheepwool]

  lua_pushlightuserdata(L, db);
  // stack: [resource_lua, render, sheepwool, db]

  lua_newtable(L);
  // stack: [resource_lua, render, sheepwool, db, context]

  pushtablestring(L, "scheme", (char *)scheme);
  pushtablestring(L, "host", host);
  pushtablestring(L, "method", method);
  pushtablestring(L, "path", path);
  /*pushtablestring(L, "remote", req->remote);*/
  pushtableint(L, "status", (int)status);

  syslog(LOG_DEBUG, "Pushing parameters");

  lua_pushliteral(L, "params");
  lua_newtable(L);
  if (req->fieldsz > 0) {
    for (size_t i = 0; i < req->fieldsz; i++) {
      if (strcmp(req->fields[i].file, "") != 0) {
        lua_pushstring(L, req->fields[i].key);
        lua_createtable(L, 0, 2);
        lua_pushstring(L, "content");
        unsigned char *encoded = malloc(b64e_size(req->fields[i].valsz) + 1);
        int encoded_size = b64_encode((const unsigned char *)req->fields[i].val,
                                      req->fields[i].valsz, encoded);
        lua_pushlstring(L, (const char *)encoded, encoded_size);
        free(encoded);
        lua_settable(L, -3);
        lua_pushstring(L, "mime");
        lua_pushstring(L, req->fields[i].ctype);
        lua_settable(L, -3);
        lua_pushstring(L, "size");
        lua_pushinteger(L, req->fields[i].valsz);
        lua_settable(L, -3);
        lua_settable(L, -3);
      } else {
        pushtablestring(L, req->fields[i].key, req->fields[i].val);
      }
    }
  }
  lua_settable(L, -3);

  syslog(LOG_DEBUG, "Pushing headers");

  lua_pushliteral(L, "headers");
  lua_newtable(L);
  if (headers.size > 0) {
    for (size_t i = 0; i < headers.size; i++) {
      h2o_header_t header = headers.entries[i];
      pushtablelstring(L, header.name->base, header.name->len,
                       header.value.base, header.value.len);
    }
  }
  lua_settable(L, -3);
  // stack: [resource_lua, render, sheepwool, db, context]

  syslog(LOG_DEBUG, "Calling render function");

  rc = lua_pcall(L, 3, 2, 0);
  if (rc != LUA_OK) {
    syslog(LOG_ERR, "Failed rendering Lua resource: %s (code: %d)",
           lua_tostring(L, -1), rc);
    goto cleanup;
  }
  // stack: [resource_lua, mime, content]

  res->mime = sqlite3_mprintf("%s", lua_tostring(L, -2));
  size_t size = 0;
  res->content = sqlite3_mprintf("%s", lua_tolstring(L, -1, &size));
  res->size = size;

cleanup:
  lua_close(L);

  return rc;
}

static int render_html_resource(sqlite3 *db, struct resource *res,
                                h2o_headers_t headers, char *host, char *method,
                                const char *scheme, char *path, char *query,
                                const int status) {
  if (res->tmpl == NULL) {
    return 0;
  }

  syslog(LOG_DEBUG, "Rendering HTML resource %s with status %d", res->slug,
         status);

  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  lua_pushlightuserdata(L, db);
  lua_pushstring(L, res->tmpl);
  lua_createtable(L, 0, 10);
  pushtableint(L, "status", (int)status);
  pushtablestring(L, "reqpath", path);
  pushtablestring(L, "scheme", (char *)scheme);
  pushtablestring(L, "baseurl", res->baseurl);
  pushtablestring(L, "slug", res->slug);
  pushtablestring(L, "srcpath", res->srcpath);
  pushtablestring(L, "name", res->name);
  pushtablelstring(L, (char *)"content", 7, res->content, res->size);
  pushtablestring(L, "ctime", res->ctime);
  pushtablestring(L, "mtime", res->mtime);
  lua_pushliteral(L, "tags");
  lua_newtable(L);
  if (res->tags) {
    for (int i = 0; res->tags[i] != NULL; i++) {
      lua_pushinteger(L, i + 1);
      lua_pushstring(L, res->tags[i]);
      lua_settable(L, -3);
    }
  }
  lua_settable(L, -3);
  // stack: [db, template_name, context]

  dumpstack(L);

  lua_render(L);

  size_t size = 0;
  res->content = sqlite3_mprintf("%s", lua_tolstring(L, -1, &size));
  res->size = size;

  lua_close(L);

  return 0;
}

static int render_resource(sqlite3 *db, struct resource *res,
                           h2o_headers_t headers, char *host, char *method,
                           const char *scheme, char *path, char *query,
                           const int status) {
  if (strcmp(res->mime, "text/html") == 0) {
    return render_html_resource(db, res, headers, host, method, scheme, path,
                                query, status);
  } else if (strcmp(res->mime, "text/x-lua") == 0) {
    return render_lua_resource(db, res, headers, host, method, scheme, path,
                               query, status);
  }

  return 0;
}

static int on_req(h2o_handler_t *self, h2o_req_t *req) {
  h2o_headers_t headers = req->headers;
  char *host = malloc(req->authority.len + 1);
  snprintf(host, req->authority.len + 1, "%s", req->authority.base);
  char *method = malloc(req->method.len + 1);
  snprintf(method, req->method.len + 1, "%s", req->method.base);
  const char *scheme = req->scheme->is_ssl ? "https" : "http";
  char *path = malloc(req->path_normalized.len + 1);
  snprintf(path, req->path_normalized.len + 1, "%s", req->path_normalized.base);
  char *query = NULL;
  if (req->query_at != SIZE_MAX) {
    query = malloc(req->path.len - req->query_at);
    snprintf(query, req->path.len - req->query_at, "%s",
             &req->path.base[req->query_at + 1]);
  }

  syslog(LOG_DEBUG, "Accepted %s request to %s", method, path);

  struct resource res;
  int status;
  int errc = 0;

  int rc = load_resource(db, &res, path);
  if (rc == SQLITE_NOTFOUND) {
    status = 404;
    errc = load_resource(db, &res, (char *)"/error");
  } else if (rc != SQLITE_OK) {
    syslog(LOG_ERR, "Failed loading resource %s: %s", path, sqlite3_errstr(rc));
    status = 500;
    errc = load_resource(db, &res, (char *)"/error");
  } else if (res.status == GONE) {
    status = 410;
    errc = load_resource(db, &res, (char *)"/error");
  } else if (res.status == MOVED) {
    status = 301;
    res.mime = sqlite3_mprintf("text/plain");
    res.content = sqlite3_mprintf("Moved to %s", res.moved_to);
    res.size = strlen(res.content);
  } else {
    status = 200;
    res.baseurl = sqlite3_mprintf("%s://%s",
                                  req->scheme->is_ssl ? "https" : "http", host);
  }

  if (errc == 0) {
    errc = render_resource(db, &res, headers, host, method, scheme, path, query,
                           status);
    if (errc) {
      status = 500;
      if (load_resource(db, &res, (char *)"/error") == 0)
        errc = render_resource(db, &res, headers, host, method, scheme, path,
                               query, status);
    }
  }

  if (errc) {
    res.mime = (char *)"text/plain";
    if (res.content == NULL || strcmp(res.content, "") == 0)
      res.content = sqlite3_mprintf("Error %d", status);
  }

  req->res.status = status;

  h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL,
                 res.mime, strlen(res.mime));

  if (res.moved_to != NULL)
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LOCATION, NULL,
                   res.moved_to, strlen(res.moved_to));

  static h2o_generator_t generator = {NULL, NULL};

  h2o_iovec_t body = h2o_strdup(&req->pool, res.content, res.size);
  h2o_start_response(req, &generator);
  h2o_send(req, &body, 1, 1);

  free_resource(&res);
  free(host);
  free(path);
  free(method);
  if (query)
    free(query);

  return 0;
}

static void on_accept(uv_stream_t *listener, int status) {
  uv_tcp_t *conn;
  h2o_socket_t *sock;

  if (status != 0)
    return;

  conn = h2o_mem_alloc(sizeof(*conn));
  uv_tcp_init(listener->loop, conn);

  if (uv_accept(listener, (uv_stream_t *)conn) != 0) {
    uv_close((uv_handle_t *)conn, (uv_close_cb)free);
    return;
  }

  sock = h2o_uv_socket_create((uv_handle_t *)conn, (uv_close_cb)free);
  h2o_accept(&accept_ctx, sock);
}

static int create_listener(void) {
  static uv_tcp_t listener;
  struct sockaddr_in addr;
  int r;

  uv_tcp_init(ctx.loop, &listener);
  uv_ip4_addr("127.0.0.1", 7890, &addr);
  if ((r = uv_tcp_bind(&listener, (struct sockaddr *)&addr, 0)) != 0) {
    syslog(LOG_ERR, "uv_tcp_bind: %s", uv_strerror(r));
    goto cleanup;
  }

  if ((r = uv_listen((uv_stream_t *)&listener, 128, on_accept)) != 0) {
    syslog(LOG_ERR, "uv_listen: %s", uv_strerror(r));
    goto cleanup;
  }

  return 0;

cleanup:
  uv_close((uv_handle_t *)&listener, NULL);
  return r;
}

int serve(char *dbpath) {
  int rc = 0;
  h2o_hostconf_t *hostconf;
  h2o_pathconf_t *pathconf;
  h2o_handler_t *handler;

  signal(SIGPIPE, SIG_IGN);

#if HAVE_PLEDGE
  syslog(LOG_DEBUG, "Pledging server access");
  if (pledge("unix sendfd recvfd inet dns proc stdio flock rpath wpath cpath "
             "fattr unveil",
             NULL) == -1) {
    syslog(LOG_ERR, "Failed pledging server access: %m");
    rc = 1;
    goto cleanup;
  }
#endif

#if HAVE_UNVEIL
  if (unveil(dirname(dbpath), "rwc") == -1) {
    syslog(LOG_ERR, "Failed unveiling database: %m");
    rc = 1;
    goto cleanup;
  }
  if (unveil("/etc/ssl/cert.pem", "r") == -1) {
    syslog(LOG_ERR, "Failed unveiling certificates");
    rc = 1;
    goto cleanup;
  }
  if (unveil(NULL, NULL) == -1) {
    syslog(LOG_ERR, "Failed closing unveils");
    rc = 1;
    goto cleanup;
  }
#endif

  rc = sqlite_connect(&db, dbpath, false);
  if (rc)
    goto cleanup;

  h2o_config_init(&config);
  hostconf = h2o_config_register_host(
      &config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

  pathconf = h2o_config_register_path(hostconf, "/", 0);
  handler = h2o_create_handler(pathconf, sizeof(*handler));
  handler->on_req = on_req;

  uv_loop_t loop;
  uv_loop_init(&loop);
  h2o_context_init(&ctx, &loop, &config);

  accept_ctx.ctx = &ctx;
  accept_ctx.hosts = config.hosts;

  if (create_listener() != 0) {
    syslog(LOG_ERR, "Failed listening to 127.0.0.1:7890: %m");
    rc = 1;
    goto cleanup;
  }

  syslog(LOG_INFO, "Server is listening on 127.0.0.1:7890");

  rc = uv_run(ctx.loop, UV_RUN_DEFAULT);

cleanup:
  sqlite_disconnect(db);
  return rc;
}
