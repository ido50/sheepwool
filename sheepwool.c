#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include <kcgi.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <magic.h>
#include <sass/base.h>
#include <sass/context.h>
#include <sqlite3.h>

#include "base64.h"
#include "etlua.h"
#include "sheepwool.h"

static void dumpstack(lua_State *L) {
  int top = lua_gettop(L);
  for (int i = 1; i <= top; i++) {
    printf("%d\t%s\t", i, luaL_typename(L, i));
    switch (lua_type(L, i)) {
    case LUA_TNUMBER:
      printf("%g\n", lua_tonumber(L, i));
      break;
    case LUA_TSTRING:
      printf("%s\n", lua_tostring(L, i));
      break;
    case LUA_TBOOLEAN:
      printf("%s\n", (lua_toboolean(L, i) ? "true" : "false"));
      break;
    case LUA_TNIL:
      printf("%s\n", "nil");
      break;
    default:
      printf("%p\n", lua_topointer(L, i));
      break;
    }
  }
}

static int sqlite_init(sqlite3 *db, bool read_only) {
  int num_cmds = read_only ? 3 : 11;

  const char *stmts[num_cmds];
  stmts[0] = "PRAGMA encoding = 'UTF-8'";
  stmts[1] = "PRAGMA foreign_keys = true";
  stmts[2] = "PRAGMA journal_mode = WAL";

  if (!read_only) {
    stmts[3] = "PRAGMA application_id = 'sheepwool'";
    stmts[4] = "PRAGMA secure_delete = 1";
    stmts[5] = "BEGIN";
    stmts[6] = "CREATE TABLE IF NOT EXISTS vars ("
               "    key             TEXT PRIMARY KEY,"
               "    value           ANY NOT NULL"
               ")";
    stmts[7] = "CREATE TABLE IF NOT EXISTS resources ("
               "    slug      TEXT PRIMARY KEY,"
               "    srcpath   TEXT,"
               "    mime      TEXT,"
               "    name      TEXT,"
               "    status    INT NOT NULL,"
               "    content   BLOB,"
               "    size      INT NOT NULL DEFAULT 0,"
               "    template  TEXT,"
               "    moved_to  TEXT,"
               "    ctime     TEXT,"
               "    mtime     TEXT"
               ")";
    stmts[8] = "CREATE TABLE IF NOT EXISTS tags ("
               "    slug      TEXT NOT NULL,"
               "    tag       TEXT NOT NULL,"
               "    PRIMARY KEY (slug, tag)"
               ")";
    stmts[9] =
        "CREATE INDEX IF NOT EXISTS resource_status ON resources(status)";
    stmts[10] = "COMMIT";
  }

  for (int i = 0; i < num_cmds; i++) {
    int rc = execute(db, stmts[i]);
    if (rc) {
      if (i > 5) {
        syslog(LOG_ERR, "Rolling back init transaction");
        execute(db, "ROLLBACK");
      }
      return rc;
    }
  }

  return 0;
}

int sqlite_connect(sqlite3 **db, char *dbpath, bool read_only) {
  syslog(LOG_DEBUG, "Connecting to database %s", dbpath);

  int rc =
      sqlite3_open_v2(dbpath, db,
                      read_only ? SQLITE_OPEN_READONLY
                                : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      NULL);
  if (rc) {
    syslog(LOG_ERR, "Failed connecting to database %s: %s", dbpath,
           sqlite3_errstr(rc));
    goto cleanup;
  }

  syslog(LOG_DEBUG, "Successfully connected to database");

  sqlite3_busy_timeout(*db, 500);

  rc = sqlite_init(*db, read_only);
  if (rc) {
    syslog(LOG_ERR, "Database initialization failed, exiting");
    goto cleanup;
  }

cleanup:
  if (rc)
    sqlite_disconnect(*db);
  return rc;
}

int sqlite_disconnect(sqlite3 *db) {
  syslog(LOG_DEBUG, "Disconnecting from database");
  return sqlite3_close(db);
}

struct bind_param sqlite_bind(int type, int int_value, double double_value,
                              char *char_value, unsigned long size) {
  struct bind_param p = {.type = type,
                         .int_value = int_value,
                         .double_value = double_value,
                         .char_value = char_value,
                         .size = size};
  return p;
}

static int bind_params(sqlite3_stmt **stmt, int num_params,
                       struct bind_param *params) {
  if (num_params == 0)
    return 0;

  for (int i = 0; i < num_params; i++) {
    int rc = 0;

    struct bind_param bp = params[i];
    switch (bp.type) {
    case SQLITE_INTEGER:
      rc = sqlite3_bind_int(*stmt, i + 1, bp.int_value);
      break;
    case SQLITE_FLOAT:
      rc = sqlite3_bind_double(*stmt, i + 1, bp.double_value);
      break;
    case SQLITE_TEXT:
      rc = sqlite3_bind_text(*stmt, i + 1, bp.char_value, -1, NULL);
      break;
    case SQLITE_BLOB:
      rc = sqlite3_bind_blob(*stmt, i + 1, bp.char_value, bp.size, NULL);
      break;
    case SQLITE_NULL:
      rc = sqlite3_bind_null(*stmt, i + 1);
      break;
    }

    if (rc) {
      return rc;
    }
  }

  return 0;
}

static int prepare_va(sqlite3 *db, sqlite3_stmt **stmt, const char *sql,
                      va_list *params) {
  syslog(LOG_DEBUG, "Preparing statement %s", sql);

  int rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
  if (rc) {
    syslog(LOG_ERR, "Failed preparing statement: %s (code: %d)",
           sqlite3_errstr(rc), rc);
    return rc;
  }

  int num_params = sqlite3_bind_parameter_count(*stmt);

  if (num_params) {
    syslog(LOG_DEBUG, "Parsing parameters for %s", sql);
    struct bind_param *params_array =
        malloc(sizeof(struct bind_param) * num_params);

    for (int i = 0; i < num_params; i++) {
      struct bind_param bp = va_arg(*params, struct bind_param);
      params_array[i] = bp;
    }

    va_end(*params);

    syslog(LOG_DEBUG, "Binding parameters for %s", sql);

    rc = bind_params(stmt, num_params, params_array);
    if (rc) {
      syslog(LOG_ERR, "Failed binding parameters: %s", sqlite3_errstr(rc));
    }

    free(params_array);
  } else {
    va_end(*params);
  }

  return rc;
}

int prepare(sqlite3 *db, sqlite3_stmt **stmt, const char *sql, ...) {
  va_list params;
  va_start(params, sql);

  return prepare_va(db, stmt, sql, &params);
}

int execute(sqlite3 *db, const char *sql, ...) {
  syslog(LOG_DEBUG, "----------------------");
  va_list params;
  va_start(params, sql);

  sqlite3_stmt *stmt;

  int rc = prepare_va(db, &stmt, sql, &params);
  if (rc) {
    goto cleanup;
  }

  syslog(LOG_DEBUG, "Executing statement %s", sql);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
    syslog(LOG_ERR, "Failed executing statement: %s (code: %d)",
           sqlite3_errstr(rc), rc);
    goto cleanup;
  }

  rc = 0;

cleanup:
  syslog(LOG_DEBUG, "Finalizing statement %s", sql);
  sqlite3_finalize(stmt);

  return rc;
}

static char *get_nullable_text(sqlite3_stmt *stmt, int col_num) {
  if (sqlite3_column_type(stmt, col_num) == SQLITE_NULL) {
    return NULL;
  }

  return sqlite3_mprintf("%s", sqlite3_column_text(stmt, col_num));
}

static void *get_nullable_blob(sqlite3_stmt *stmt, int col_num) {
  if (sqlite3_column_type(stmt, col_num) == SQLITE_NULL) {
    return NULL;
  }

  const char *blob = sqlite3_column_blob(stmt, col_num);
  int blob_size = sqlite3_column_bytes(stmt, col_num);
  char *dest = sqlite3_malloc(blob_size);
  memcpy(dest, blob, blob_size);

  return dest;
}

static void pushtablestring(lua_State *L, const char *key, char *value) {
  lua_pushstring(L, key);
  lua_pushstring(L, value);
  lua_settable(L, -3);
}

static void pushtablelstring(lua_State *L, const char *key, char *value,
                             int size) {
  lua_pushstring(L, key);
  lua_pushlstring(L, value, size);
  lua_settable(L, -3);
}

static void pushtableint(lua_State *L, const char *key, int value) {
  lua_pushstring(L, key);
  lua_pushinteger(L, value);
  lua_settable(L, -3);
}

static int open_etlua(lua_State *L) {
  if (luaL_loadstring(L, (const char *)etlua) != LUA_OK) {
    return lua_error(L);
  }
  lua_call(L, 0, 1);
  return 1;
}

static int lua_render(lua_State *L) {
  // stack: [db, slug, context]

  sqlite3 *db = (sqlite3 *)lua_touserdata(L, 1);
  char *tmpl_name = sqlite3_mprintf("%s", lua_tostring(L, 2));

  syslog(LOG_DEBUG, "Rendering template %s", tmpl_name);

  luaL_requiref(L, "etlua", open_etlua, 0);
  // stack: [db, slug, context, etlua]

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db,
                              "SELECT content, template"
                              "  FROM resources"
                              " WHERE slug = ?",
                              -1, &stmt, NULL);
  if (rc) {
    lua_pushfstring(L, "Failed preparing template statement: %s",
                    sqlite3_errstr(rc));
    goto cleanup;
  }

  while (true) {
    if (lua_getfield(L, 4, "render") != LUA_TFUNCTION) {
      lua_pushfstring(L, "Failed getting render function: got %s",
                      lua_typename(L, lua_type(L, -1)));
      goto cleanup;
    }
    // stack: [db, slug, context, etlua, render]

    rc = sqlite3_bind_text(stmt, 1, tmpl_name, -1, NULL);
    if (rc) {
      lua_pushfstring(L, "Failed binding template slug: %s",
                      sqlite3_errstr(rc));
      goto cleanup;
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
      lua_pushfstring(L, "Failed loading template %s: %s", tmpl_name,
                      sqlite3_errstr(rc));
      goto cleanup;
    }

    if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
      lua_pushfstring(L, "Failed getting template: content is NULL");
      goto cleanup;
    }

    const void *tmpl = sqlite3_column_blob(stmt, 0);
    int tmpl_size = sqlite3_column_bytes(stmt, 0);

    lua_pushlstring(L, tmpl, tmpl_size);
    // stack: [db, slug, context, etlua, render, template]

    sqlite3_free(tmpl_name);
    tmpl_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 1));

    lua_pushnil(L);
    lua_copy(L, 3, 7);
    // stack: [db, slug, context, etlua, render, template, context]

    rc = lua_pcall(L, 2, 1, 0);
    if (rc != LUA_OK) {
      lua_pushfstring(L, "Failed rendering template: %s", lua_tostring(L, -1));
      goto cleanup;
    }
    // stack: [db, slug, context, etlua, output]

    if (lua_isnil(L, -1)) {
      lua_pushfstring(L, "Failed rendering template: got nil");
      goto cleanup;
    }

    if (strcmp(tmpl_name, "") != 0) {
      lua_setfield(L, 3, "content");
      sqlite3_reset(stmt);
      continue;
      // stack: [db, slug, context, etlua]
    }

    break;
  }

cleanup:
  sqlite3_free(tmpl_name);
  syslog(LOG_DEBUG, "Finalizing lua_render statement");
  sqlite3_finalize(stmt);
  if (rc)
    return lua_error(L);

  return 1;
}

bool match(lua_State *L, char *str, const char *pattern) {
  lua_getglobal(L, "string");
  lua_getfield(L, 1, "match");
  lua_pushstring(L, str);
  lua_pushstring(L, pattern);

  bool matched = lua_pcall(L, 2, 1, 0) == LUA_OK && lua_isstring(L, -1);

  lua_pop(L, 2);

  return matched;
}

char *replace(lua_State *L, char *str, const char *pattern, const char *repl) {
  lua_getglobal(L, "string");
  lua_getfield(L, 1, "gsub");
  lua_pushstring(L, str);
  lua_pushstring(L, pattern);
  lua_pushstring(L, repl);

  char *result = NULL;
  if (lua_pcall(L, 3, 1, 0) == LUA_OK && lua_isstring(L, -1)) {
    result = sqlite3_mprintf("%s", lua_tostring(L, -1));
  }

  lua_pop(L, 2);

  return result;
}

static char *mime_type(lua_State *L, char *path) {
  syslog(LOG_DEBUG, "Calculating MIME type for %s", path);

  magic_t cookie = magic_open(MAGIC_MIME_TYPE);
  if (cookie == NULL) {
    syslog(LOG_ERR, "Failed opening libmagic cookie: %m");
    return NULL;
  }

  char *result = NULL;

  if (magic_load(cookie, NULL) != 0) {
    syslog(LOG_ERR, "Failed loading libmagic DB: %s", magic_error(cookie));
    goto cleanup;
  }

  const char *mime = magic_file(cookie, path);
  if (mime == NULL) {
    syslog(LOG_ERR, "Failed parsing magic file: %s", magic_error(cookie));
    goto cleanup;
  }

  if (strcmp(mime, "text/plain") == 0) {
    if (match(L, path, "%.css$")) {
      mime = "text/css";
    } else if (match(L, path, "%.lua$")) {
      mime = "text/x-lua";
    }
  }

  result = sqlite3_mprintf("%s", mime);

  syslog(LOG_DEBUG, "MIME type of %s is %s", path, result);

cleanup:
  magic_close(cookie);

  return result;
}

static char *parse_time(time_t time) {
  syslog(LOG_ERR, "Parsing time %ld", time);
  size_t size = sizeof("2022-01-01T00:00:00");
  char *target = sqlite3_malloc(size);
  strftime(target, size, "%Y-%m-%dT%H:%M:%S", gmtime(&time));
  return target;
}

static int parse_html(lua_State *L, struct resource *res, char *abspath) {
  syslog(LOG_DEBUG, "Parsing HTML file %s", abspath);

  res->slug = replace(L, res->slug, "%.html$", "");
  res->mime = sqlite3_mprintf("text/html");

  const char *keys[] = {"name", "template", "status", "tags", "ctime", "mtime"};
  for (int i = 0; i < 6; i++) {
    lua_getglobal(L, "string");
    lua_getfield(L, 1, "match");
    lua_pushstring(L, res->content);
    lua_pushfstring(L, "<!%%-%%- %s: ([^>]+) %%-%%->", keys[i]);

    if (lua_pcall(L, 2, 1, 0) == LUA_OK) {
      if (lua_isnil(L, -1)) {
        continue;
      }

      char *value = sqlite3_mprintf("%s", lua_tostring(L, -1));

      if (strcmp(keys[i], "name") == 0) {
        res->name = value;
      } else if (strcmp(keys[i], "template") == 0) {
        res->tmpl = value;
      } else if (strcmp(keys[i], "status") == 0) {
        if (strcmp(value, "unpub") == 0) {
          res->status = UNPUB;
        } else if (strcmp(value, "gone") == 0) {
          res->status = GONE;
        } else if (strcmp(value, "moved") == 0) {
          res->status = MOVED;
        } else {
          res->status = PUB;
        }
      } else if (strcmp(keys[i], "tags") == 0) {
        int i = 0;
        char *tag = strtok(value, ", ");
        while (tag) {
          // we are allocating enough memory for one tag (or the number of tags
          // we have) plus one NULL pointer (sentinel)
          if (i)
            res->tags = sqlite3_realloc(res->tags, sizeof(char *) * (i + 2));
          else
            res->tags = sqlite3_malloc(sizeof(char *) * 2);
          res->tags[i] = tag;
          tag = strtok(NULL, ", ");
          i++;
        }
        res->tags[i] = NULL;
      } else if (strcmp(keys[i], "ctime") == 0) {
        res->ctime = value;
      } else if (strcmp(keys[i], "mtime") == 0) {
        res->mtime = value;
      } else {
        sqlite3_free(value);
      }

      lua_pop(L, 1);
    }
  }

  lua_pop(L, lua_gettop(L));

  return 0;
}

static int parse_scss(lua_State *L, struct resource *res, char *abspath) {
  syslog(LOG_DEBUG, "Parsing SCSS file %s", abspath);

  struct Sass_Options *options = sass_make_options();
  sass_option_set_output_style(options, SASS_STYLE_COMPRESSED);
  sass_option_set_precision(options, 10);

  struct Sass_Data_Context *ctx =
      sass_make_data_context(strndup(res->content, res->size));
  struct Sass_Context *ctx_out = sass_data_context_get_context(ctx);
  sass_data_context_set_options(ctx, options);
  sass_compile_data_context(ctx);

  int rc = 0;

  if (sass_context_get_error_status(ctx_out)) {
    const char *error_message = sass_context_get_error_message(ctx_out);
    if (error_message) {
      syslog(LOG_ERR, "Failed parsing SCSS: %s", error_message);
    } else {
      syslog(LOG_ERR, "Failed parsing SCSS: no error message available");
    }
    rc = 1;
    goto cleanup;
  }

  res->content = sqlite3_mprintf("%s", sass_context_get_output_string(ctx_out));
  res->slug = replace(L, res->slug, "%.scss$", ".css");
  res->mime = sqlite3_mprintf("text/css");
  res->size = strlen(res->content);

cleanup:
  sass_delete_data_context(ctx);

  return rc;
}

static int parse_sql(sqlite3 *db, lua_State *L, struct resource *res,
                     char *abspath) {
  syslog(LOG_DEBUG, "Importing SQL statements from %s", abspath);

  const char *stmts[] = {"BEGIN", res->content, "COMMIT"};

  int rc = 0;

  for (int i = 0; i < 3; i++) {
    char *stmt = strtok((char *)stmts[i], ";");
    while (stmt && !match(L, stmt, "^%s+$")) {
      rc = execute(db, stmt);
      if (rc) {
        syslog(LOG_ERR, "Failed importing %s: %s", abspath, sqlite3_errstr(rc));
        if (i > 0) {
          execute(db, "ROLLBACK");
        }
        goto cleanup;
      }

      stmt = strtok(NULL, ";");
    }
  }

cleanup:
  free_resource(res);

  return rc;
}

static void remove_newline(char *input) {
  char *pch = strstr(input, "\n");
  if (pch != NULL)
    strncpy(pch, "\0", 1);
}

static int import_meta(lua_State *L, sqlite3 *db, char *abspath) {
  syslog(LOG_DEBUG, "Importing META file");

  sqlite3_stmt *stmt;
  FILE *fd = NULL;
  char *line = NULL;
  bool opened_file = false;

  int rc = sqlite3_prepare_v2(db,
                              "REPLACE INTO resources(slug, status, moved_to)"
                              "      VALUES (?, ?, ?)",
                              -1, &stmt, NULL);
  if (rc) {
    syslog(LOG_ERR, "META: Failed preparing statement: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  fd = fopen(abspath, "r");
  if (fd == NULL) {
    rc = errno;
    syslog(LOG_ERR, "META: Failed opening file %s: %m", abspath);
    goto cleanup;
  }

  opened_file = true;

  size_t len = 0;
  while (getline(&line, &len, fd) != -1) {
    char *token = strtok(line, " ");
    int i = 0;
    while (token) {
      remove_newline(token);
      switch (i) {
      case 0:
        rc = sqlite3_bind_text(stmt, 1, token, -1, NULL);
        break;
      case 1:
        if (strcmp(token, "permanent") == 0) {
          rc = sqlite3_bind_int(stmt, 2, MOVED);
        } else if (strcmp(token, "gone") == 0) {
          rc = sqlite3_bind_int(stmt, 2, GONE);
        } else if (strcmp(token, "not_found") == 0) {
          rc = sqlite3_bind_int(stmt, 2, UNPUB);
        } else {
          syslog(LOG_ERR, "META: Invalid status %s in line %s", token, line);
          rc = 1;
          goto cleanup;
        }
        break;
      case 2:
        rc = sqlite3_bind_text(stmt, 3, token, -1, NULL);
        break;
      default:
        syslog(LOG_ERR, "META: Invalid line %s", line);
        rc = 1;
        goto cleanup;
      }

      if (rc) {
        syslog(LOG_ERR, "META: Failed binding %d: %s", i, sqlite3_errstr(rc));
        goto cleanup;
      }

      token = strtok(NULL, " ");
      i++;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
      syslog(LOG_ERR, "META: Failed executing statement: %s",
             sqlite3_errstr(rc));
      goto cleanup;
    }

    rc = 0;

    sqlite3_reset(stmt);
  }

cleanup:
  syslog(LOG_DEBUG, "META: Finalizing statement");
  sqlite3_finalize(stmt);
  if (opened_file)
    fclose(fd);
  if (line)
    free(line);

  return rc;
}

static int import_file(lua_State *L, sqlite3 *db, char *root, char *abspath,
                       char *relpath, struct stat fstat) {
  syslog(LOG_DEBUG, "Importing file %s", abspath);

  struct resource res = {.srcpath = sqlite3_mprintf("%s", relpath),
                         .slug = sqlite3_mprintf("%s", relpath),
                         .mime = mime_type(L, abspath),
                         .baseurl = NULL,
                         .name = sqlite3_mprintf("%s", basename(relpath)),
                         .status = 0,
                         .tmpl = NULL,
                         .moved_to = NULL,
                         .content = NULL,
                         .ctime = parse_time(fstat.st_mtime),
                         .mtime = parse_time(fstat.st_mtime)};

  FILE *fd;
  int rc = 0;
  bool file_opened = false;
  bool file_closed = false;
  bool txn_began = false;
  bool txn_committed = false;

  fd = fopen(abspath, "rb");
  if (fd == 0) {
    rc = errno;
    syslog(LOG_ERR, "Failed opening file %s: %m", abspath);
    goto cleanup;
  }

  file_opened = true;

  res.content = sqlite3_malloc(fstat.st_size + 1);
  if (res.content == 0) {
    rc = errno;
    syslog(LOG_ERR, "Failed allocating memory for file %s: %m", abspath);
    goto cleanup;
  }

  if (fstat.st_size > 0 && fread(res.content, fstat.st_size, 1, fd) != 1) {
    rc = errno;
    syslog(LOG_ERR, "Failed reading file %s: %m", abspath);
    goto cleanup;
  }

  res.content[fstat.st_size] = '\0';

  fclose(fd);
  file_closed = true;

  res.size = fstat.st_size;

  if (strcmp(res.name, "import.sql") == 0) {
    return parse_sql(db, L, &res, abspath);
  } else if (match(L, abspath, "%.html$")) {
    rc = parse_html(L, &res, abspath);
    if (rc) {
      syslog(LOG_ERR, "Failed parsing HTML file %s: %d", abspath, rc);
      goto cleanup;
    }
  } else if (match(L, abspath, "%.scss$")) {
    rc = parse_scss(L, &res, abspath);
    if (rc) {
      syslog(LOG_ERR, "Failed parsing SCSS file %s: %d", abspath, rc);
      goto cleanup;
    }
  } else if (match(L, abspath, "%.lua$")) {
    sqlite3_free(res.mime);
    res.mime = sqlite3_mprintf("text/x-lua");
    res.slug = replace(L, res.slug, "%.lua$", "");
  }

  if (match(L, res.slug, "/index$")) {
    if (!match(L, res.slug, "^/templates/index$")) {
      res.slug = replace(L, res.slug, "/index$", "");
      if (strcmp(res.slug, "") == 0) {
        res.slug = sqlite3_mprintf("/");
      }
    }
  }

  rc = execute(db, "BEGIN");
  if (rc) {
    goto cleanup;
  }

  txn_began = true;

  rc = execute(db,
               "INSERT OR REPLACE INTO resources "
               "(slug, srcpath, mime, name, status, content, size, template, "
               "moved_to, "
               " ctime, mtime) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
               sqlite_bind(SQLITE_TEXT, 0, 0, res.slug, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.srcpath, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.mime, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.name, 0),
               sqlite_bind(SQLITE_INTEGER, res.status, 0, NULL, 0),
               sqlite_bind(SQLITE_BLOB, 0, 0, res.content, res.size),
               sqlite_bind(SQLITE_INTEGER, res.size, 0, NULL, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.tmpl, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.moved_to, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.ctime, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res.mtime, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed inserting to database: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  rc = execute(db, "DELETE FROM tags WHERE slug=?",
               sqlite_bind(SQLITE_TEXT, 0, 0, res.slug, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed removing existing tags: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  if (res.tags) {
    for (int i = 0; res.tags[i] != NULL; i++) {
      rc = execute(db, "INSERT INTO tags VALUES (?, ?)",
                   sqlite_bind(SQLITE_TEXT, 0, 0, res.slug, 0),
                   sqlite_bind(SQLITE_TEXT, 0, 0, res.tags[i], 0));
      if (rc) {
        syslog(LOG_ERR, "Failed inserting tag %s: %s", res.tags[i],
               sqlite3_errstr(rc));
        goto cleanup;
      }
    }
  }

  rc = execute(db, "COMMIT");
  if (rc) {
    syslog(LOG_ERR, "Failed committing transaction: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  txn_committed = true;

cleanup:
  if (file_opened && !file_closed)
    fclose(fd);
  if (txn_began && !txn_committed)
    execute(db, "ROLLBACK");
  free_resource(&res);

  return rc;
}

static int build_dir(lua_State *L, sqlite3 *db, char *root, char *relpath) {
  int rc = 0;

  char *abspath = NULL;
  char *absfilepath = NULL;
  char *relfilepath = NULL;

  if (relpath == NULL) {
    abspath = sqlite3_mprintf("%s", root);
  } else {
    abspath = sqlite3_mprintf("%s/%s", root, relpath);
  }

  syslog(LOG_DEBUG, "Building directory %s", abspath);

  DIR *dir = opendir(abspath);
  if (dir == NULL) {
    rc = 1;
    syslog(LOG_ERR, "Failed opening directory %s: %m", abspath);
    goto cleanup;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;

    syslog(LOG_DEBUG, "Working on entry %s", entry->d_name);

    absfilepath = sqlite3_mprintf("%s/%s", abspath, entry->d_name);
    relfilepath = sqlite3_mprintf("%s/%s", relpath, entry->d_name);

    struct stat fstat;
    rc = lstat(absfilepath, &fstat);
    if (rc) {
      syslog(LOG_ERR, "Failed running lstat on %s: %m", absfilepath);
      goto loopcleanup;
    }

    if (S_ISDIR(fstat.st_mode) || entry->d_type == DT_DIR) {
      lua_pop(L, lua_gettop(L));
      rc = build_dir(L, db, root, relfilepath);
      if (rc) {
        syslog(LOG_ERR, "Failed building directory %s: %m", absfilepath);
        goto loopcleanup;
      }
    } else if (S_ISREG(fstat.st_mode) || entry->d_type == DT_REG) {
      lua_pop(L, lua_gettop(L));

      if (relpath == NULL && strcmp(relfilepath, "/META") == 0) {
        rc = import_meta(L, db, absfilepath);
      } else {
        rc = import_file(L, db, root, absfilepath, relfilepath, fstat);
      }
      if (rc) {
        syslog(LOG_ERR, "Failed importing file %s: %m", absfilepath);
        goto loopcleanup;
      }
    }

  loopcleanup:
    sqlite3_free(relfilepath);
    sqlite3_free(absfilepath);
    if (rc)
      goto cleanup;
  }

cleanup:
  closedir(dir);
  sqlite3_free(abspath);

  return rc;
}

static int generate_sitemap(sqlite3 *db) {
  syslog(LOG_DEBUG, "Generating sitemap.xml");

  const char *template =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
      "    <% for i = 1, #resources do %>\n"
      "    <url>\n"
      "        <loc><%= baseurl %><%= resources[i].slug %></loc>\n"
      "        <lastmod><%= resources[i].mtime %></lastmod>\n"
      "    </url>\n"
      "    <% end %>\n"
      "</urlset>";
  size_t tmpl_size = strlen(template);

  int rc = execute(db,
                   "INSERT OR REPLACE INTO resources"
                   "(slug, mime, status, content, size)"
                   "VALUES ('system:/sitemap.xml', 'application/xml', ?, ?, ?)",
                   sqlite_bind(SQLITE_INTEGER, PUB, 0, NULL, 0),
                   sqlite_bind(SQLITE_BLOB, 0, 0, (char *)template, tmpl_size),
                   sqlite_bind(SQLITE_INTEGER, tmpl_size, 0, NULL, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed inserting sitemap template: %s",
           sqlite3_errstr(rc));
    goto cleanup;
  }

  const char *content = "function render(sheepwool, db, req)\n"
                        "    local resources = sheepwool.query(db, [[\n"
                        "        SELECT slug, mtime\n"
                        "        FROM resources\n"
                        "        WHERE slug NOT LIKE '/templates/%'\n"
                        "          AND status = 0\n"
                        "          AND mime IN ('text/html', 'text/x-lua')\n"
                        "        ORDER BY slug\n"
                        "    ]])\n"
                        "\n"
                        "    local context = {\n"
                        "        [\"name\"] = \"Sitemap\",\n"
                        "        [\"resources\"] = resources,\n"
                        "        [\"baseurl\"] = string.format(\"%s://%s%s\", "
                        "req.scheme, req.host, req.root),\n"
                        "    }\n"
                        "\n"
                        "    return \"application/xml\", sheepwool.render(db, "
                        "\"system:/sitemap.xml\", context)\n"
                        "end\n"
                        "\n"
                        "return {\n"
                        "    [\"render\"] = render,\n"
                        "}\n";
  size_t size = strlen(content);

  rc = execute(
      db,
      "INSERT OR REPLACE INTO resources "
      "(slug, mime, name, ctime, mtime, content, size, status, template)"
      "VALUES ('/sitemap.xml', 'text/x-lua', 'Sitemap', "
      "strftime('%Y-%m-%dT%H:%M:%S'), strftime('%Y-%m-%dT%H:%M:%S'), ?, ?, ?, "
      "?)",
      sqlite_bind(SQLITE_BLOB, 0, 0, (char *)content, size),
      sqlite_bind(SQLITE_INTEGER, size, 0, NULL, 0),
      sqlite_bind(SQLITE_INTEGER, PUB, 0, NULL, 0),
      sqlite_bind(SQLITE_TEXT, 0, 0, (char *)"system:/sitemap.xml", 0));
  if (rc) {
    syslog(LOG_ERR, "Failed inserting sitemap to database: %s",
           sqlite3_errstr(rc));
    goto cleanup;
  }

cleanup:
  return rc;
}

int fsbuild(char *dbpath, char *root) {
  int rc = 0;
  lua_State *L = 0;

  syslog(LOG_INFO, "Building database %s from %s", dbpath, root);

#if HAVE_PLEDGE
  syslog(LOG_DEBUG, "Pleding build access");
  if (pledge("stdio rpath wpath cpath flock fattr unveil", NULL) == -1) {
    syslog(LOG_ERR, "Failed pledging: %m");
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
  if (unveil(root, "r") == -1) {
    syslog(LOG_ERR, "Failed unveiling source directory: %m");
    rc = 1;
    goto cleanup;
  }
  if (unveil("/usr/local/share/misc/magic.mgc", "r") == -1) {
    syslog(LOG_ERR, "Failed unveiling magic database: %m");
    rc = 1;
    goto cleanup;
  }
  if (unveil(NULL, NULL) == -1) {
    syslog(LOG_ERR, "Failed closing unveil: %m");
    rc = 1;
    goto cleanup;
  }
#endif

  sqlite3 *db;
  rc = sqlite_connect(&db, dbpath, false);
  if (rc)
    goto cleanup;

  syslog(LOG_DEBUG, "Creating Lua state");
  L = luaL_newstate();
  luaL_openlibs(L);

  rc = build_dir(L, db, root, NULL);
  if (rc)
    goto cleanup;

  rc = generate_sitemap(db);
  if (rc)
    goto cleanup;

cleanup:
  if (L)
    lua_close(L);
  if (db)
    sqlite_disconnect(db);

  return rc;
}

static void http_open(struct kreq *r, enum khttp code, char *mime) {
  khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[code]);
  khttp_head(r, kresps[KRESP_CONTENT_TYPE], "%s", mime);
  khttp_head(r, "X-Content-Type-Options", "nosniff");
  khttp_head(r, "X-Frame-Options", "DENY");
  khttp_head(r, "X-XSS-Protection", "1; mode=block");
}

const int khttpd[KHTTP__MAX] = {
    100, /* KHTTP_100 */
    101, /* KHTTP_101 */
    103, /* KHTTP_103 */
    200, /* KHTTP_200 */
    201, /* KHTTP_201 */
    202, /* KHTTP_202 */
    203, /* KHTTP_203 */
    204, /* KHTTP_204 */
    205, /* KHTTP_205 */
    206, /* KHTTP_206 */
    207, /* KHTTP_207 */
    300, /* KHTTP_300 */
    301, /* KHTTP_301 */
    302, /* KHTTP_302 */
    303, /* KHTTP_303 */
    304, /* KHTTP_304 */
    306, /* KHTTP_306 */
    307, /* KHTTP_307 */
    308, /* KHTTP_308 */
    400, /* KHTTP_400 */
    401, /* KHTTP_401 */
    402, /* KHTTP_402 */
    403, /* KHTTP_403 */
    404, /* KHTTP_404 */
    405, /* KHTTP_405 */
    406, /* KHTTP_406 */
    407, /* KHTTP_407 */
    408, /* KHTTP_408 */
    409, /* KHTTP_409 */
    410, /* KHTTP_410 */
    411, /* KHTTP_411 */
    412, /* KHTTP_412 */
    413, /* KHTTP_413 */
    414, /* KHTTP_414 */
    415, /* KHTTP_415 */
    416, /* KHTTP_416 */
    417, /* KHTTP_417 */
    424, /* KHTTP_424 */
    428, /* KHTTP_428 */
    429, /* KHTTP_429 */
    431, /* KHTTP_431 */
    500, /* KHTTP_500 */
    501, /* KHTTP_501 */
    502, /* KHTTP_502 */
    503, /* KHTTP_503 */
    504, /* KHTTP_504 */
    505, /* KHTTP_505 */
    507, /* KHTTP_507 */
    511, /* KHTTP_511 */
};

int serve(char *dbpath) {
  int rc = 0;

  sqlite3 *db;
  struct kreq req;
  struct kfcgi *fcgi;

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

  syslog(LOG_DEBUG, "Initializing FastCGI daemon");
  rc = khttp_fcgi_init(&fcgi, NULL, 0, NULL, 0, 0);
  if (rc != KCGI_OK)
    goto cleanup;

#if HAVE_PLEDGE
  syslog(LOG_DEBUG, "Reducing pledge access");
  if (pledge("stdio recvfd inet dns flock rpath wpath cpath fattr", NULL) ==
      -1) {
    syslog(LOG_ERR, "Failed reducing pledge access: %m");
    rc = 1;
    goto cleanup;
  }
#endif

  while (khttp_fcgi_parse(fcgi, &req) == KCGI_OK) {
    syslog(LOG_DEBUG, "Accepted %s request to %s", kmethods[req.method],
           req.fullpath);

    struct resource res;
    enum khttp status;
    int errc = 0;

    int rc = load_resource(db, &res, req.fullpath);
    if (rc == SQLITE_NOTFOUND) {
      status = KHTTP_404;
      errc = load_resource(db, &res, (char *)"/error");
    } else if (rc != SQLITE_OK) {
      syslog(LOG_ERR, "Failed loading resource %s: %s", req.fullpath,
             sqlite3_errstr(rc));
      status = KHTTP_500;
      errc = load_resource(db, &res, (char *)"/error");
    } else if (res.status == GONE) {
      status = KHTTP_410;
      errc = load_resource(db, &res, (char *)"/error");
    } else if (res.status == MOVED) {
      status = KHTTP_301;
      res.mime = sqlite3_mprintf("text/plain");
      res.content = sqlite3_mprintf("Moved to %s", res.moved_to);
      res.size = strlen(res.content);
    } else {
      status = KHTTP_200;
      res.baseurl = sqlite3_mprintf(
          "%s://%s", req.scheme == KSCHEME_HTTPS ? "https" : "http", req.host);
    }

    if (errc == 0) {
      errc = render_resource(db, &res, &req, status);
      if (errc) {
        status = KHTTP_500;
        if (load_resource(db, &res, (char *)"/error") == 0)
          errc = render_resource(db, &res, &req, status);
      }
    }

    if (errc) {
      http_open(&req, status, (char *)"text/plain");
      khttp_body(&req);
      if (res.content == NULL || strcmp(res.content, "") == 0) {
        khttp_puts(&req, khttps[status]);
      } else {
        khttp_puts(&req, res.content);
      }
      khttp_free(&req);
      continue;
    }

    http_open(&req, status, res.mime);
    if (res.moved_to != NULL) {
      khttp_head(&req, "Location", "%s", res.moved_to);
    }

    khttp_body(&req);
    khttp_write(&req, res.content, res.size);
    khttp_free(&req);
    free_resource(&res);
  }

cleanup:
  syslog(LOG_DEBUG, "Freeing FastCGI resources");
  khttp_fcgi_free(fcgi);
  sqlite_disconnect(db);

  return rc;
}

int load_resource(sqlite3 *db, struct resource *res, char *slug) {
  syslog(LOG_DEBUG, "Loading resource %s", slug);

  int rc = 0;

  char *sslug = strdup(slug);
  if (strcmp(sslug, "") == 0)
    sslug = strdup("/");

  sqlite3_stmt *stmt;
  rc = prepare(
      db, &stmt,
      "    SELECT r.slug, r.srcpath, r.name, r.mime, r.status, r.content,"
      "           r.size, r.template, r.moved_to, r.ctime, r.mtime,"
      "           group_concat(t.tag) AS tags"
      "      FROM resources r"
      " LEFT JOIN tags t ON t.slug = r.slug"
      "     WHERE r.slug = ? AND r.status != ?"
      "  GROUP BY r.slug",
      sqlite_bind(SQLITE_TEXT, 0, 0, sslug, 0),
      sqlite_bind(SQLITE_INTEGER, UNPUB, 0, NULL, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed preparing resource loading statement: %s",
           sqlite3_errstr(rc));
    goto cleanup;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    rc = SQLITE_NOTFOUND;
    goto cleanup;
  }

  rc = 0;

  res->slug = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 0));

  if (strcmp(res->slug, "") == 0) {
    rc = SQLITE_NOTFOUND;
    goto cleanup;
  }

  res->srcpath = get_nullable_text(stmt, 1);
  res->name = get_nullable_text(stmt, 2);
  res->mime = get_nullable_text(stmt, 3);
  res->status = sqlite3_column_int(stmt, 4);
  res->content = get_nullable_blob(stmt, 5);
  res->size = sqlite3_column_int(stmt, 6);
  res->tmpl = get_nullable_text(stmt, 7);
  res->moved_to = get_nullable_text(stmt, 8);
  res->ctime = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 9));
  res->mtime = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 10));
  res->baseurl = NULL;
  res->tags = NULL;
  char *tags = get_nullable_text(stmt, 11);
  if (tags != NULL) {
    char *tag = strtok(tags, ",");
    int i = 0;
    while (tag) {
      // we are allocating enough memory for the tags, plus a NULL sentinel
      if (i)
        res->tags = sqlite3_realloc(res->tags, sizeof(res->tags) * (i + 2));
      else
        res->tags = sqlite3_malloc(sizeof(res->tags) * 2);
      res->tags[i] = tag;
      tag = strtok(NULL, ",");
      i++;
    }
    res->tags[i] = NULL;
  }

cleanup:
  free(sslug);
  syslog(LOG_DEBUG, "Finalizing load_resource statement");
  sqlite3_finalize(stmt);

  return rc;
}

static int lua_base64_encode(lua_State *L) {
  size_t size;
  const char *input = luaL_checklstring(L, 1, &size);

  unsigned char *encoded = malloc(b64e_size(size) + 1);
  int encoded_size = b64_encode((const unsigned char *)input, size, encoded);

  lua_pushlstring(L, (const char *)encoded, encoded_size);

  return 1;
}

static int lua_query(lua_State *L) {
  if (!lua_islightuserdata(L, 1)) {
    return luaL_argerror(L, 1, "must be a database connection");
  }

  sqlite3 *db = (sqlite3 *)lua_touserdata(L, 1);
  const char *sql = luaL_checkstring(L, 2);

  int rc = 0;
  sqlite3_stmt *stmt;
  struct bind_param *params = 0;

  syslog(LOG_DEBUG, "Preparing statement %s", sql);
  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc) {
    lua_pushfstring(L, "prepare failed: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  int num_params = sqlite3_bind_parameter_count(stmt);

  params = malloc(sizeof(struct bind_param) * num_params);

  if (num_params > 0 && num_params < MAX_PARAMS) {
    syslog(LOG_DEBUG, "Binding parameters");
    for (int i = 0; i < num_params; i++) {
      int si = i + 3;
      switch (lua_type(L, si)) {
      case LUA_TSTRING:
        params[i] =
            sqlite_bind(SQLITE_TEXT, 0, 0, (char *)lua_tostring(L, si), 0);
        break;
      case LUA_TBOOLEAN:
        params[i] =
            sqlite_bind(SQLITE_INTEGER, lua_toboolean(L, si), 0, NULL, 0);
        break;
      case LUA_TNUMBER:
        if (lua_isinteger(L, si)) {
          params[i] =
              sqlite_bind(SQLITE_INTEGER, lua_tointeger(L, si), 0, NULL, 0);
          break;
        } else {
          params[i] =
              sqlite_bind(SQLITE_FLOAT, 0, lua_tonumber(L, si), NULL, 0);
          break;
        }
      case LUA_TNIL:
        params[i] = sqlite_bind(SQLITE_NULL, 0, 0, NULL, 0);
        break;
      }
    }

    rc = bind_params(&stmt, num_params, params);
    if (rc) {
      lua_pushfstring(L, "Failed biding parameters: %s", sqlite3_errstr(rc));
      goto cleanup;
    }
  }

  int num_rows = 0;

  lua_newtable(L);

  while (true) {
    syslog(LOG_DEBUG, "Stepping through results");
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
      rc = 0;
      break;
    } else if (rc != SQLITE_ROW) {
      lua_pushfstring(L, "Failed executing statement: %s", sqlite3_errstr(rc));
      goto cleanup;
    }

    syslog(LOG_DEBUG, "Parsing result columns");
    num_rows++;
    int num_cols = sqlite3_column_count(stmt);
    lua_pushinteger(L, num_rows);
    lua_createtable(L, num_cols, 0);
    for (int i = 0; i < num_cols; i++) {
      lua_pushstring(L, sqlite3_column_name(stmt, i));
      switch (sqlite3_column_type(stmt, i)) {
      case SQLITE_TEXT:
        lua_pushstring(L, (char *)sqlite3_column_text(stmt, i));
        break;
      case SQLITE_INTEGER:
        lua_pushinteger(L, sqlite3_column_int(stmt, i));
        break;
      case SQLITE_FLOAT:
        lua_pushnumber(L, sqlite3_column_double(stmt, i));
        break;
      case SQLITE_BLOB:
        lua_pushlightuserdata(L, (void *)sqlite3_column_blob(stmt, i));
        break;
      case SQLITE_NULL:
        lua_pushnil(L);
        break;
      default:
        rc = 1;
        lua_pushfstring(L, "Unknown column return type for %d", i);
        goto cleanup;
      }
      lua_settable(L, -3);
    }
    lua_settable(L, -3);
    rc = 0;
  }

cleanup:
  syslog(LOG_DEBUG, "Finalizing statement %s", sql);
  sqlite3_finalize(stmt);

  if (params)
    free(params);
  if (rc)
    return lua_error(L);

  return 1;
}

static unsigned char *read_fd(lua_State *L, int fd, int *size) {
  unsigned char *output;

  while (true) {
    const size_t read_size = 512;
    unsigned char buf[read_size];
    int nread = read(fd, buf, read_size);
    switch (nread) {
    case -1:
      if (errno == EAGAIN) {
        sleep(1);
        break;
      } else {
        lua_pushfstring(L, "Failed reading command stdout: %s (code: %d)",
                        strerror(errno), errno);
        return NULL;
      }
    case 0:
      output[*size] = 0;
      *size += 1;
      close(fd);
      return output;
    default:
      if (*size)
        output = realloc(output, *size + nread + 1);
      else
        output = malloc(nread + 1);

      if (*size == 0) {
        memcpy(output, buf, nread);
      } else {
        memcpy(output + *size - 1, buf, nread);
      }

      *size += nread;
      break;
    }
  }
}

static int lua_execute(lua_State *L) {
  syslog(LOG_DEBUG, "Executing command");

  bool has_stdin = lua_gettop(L) == 3;

  const char *cmd = luaL_checkstring(L, 1);

  int num_args = luaL_len(L, 2);
  char *argv[num_args + 2];
  argv[0] = (char *)cmd;
  for (int i = 0; i < num_args; i++) {
    lua_pushinteger(L, i + 1);
    lua_gettable(L, 2);
    argv[i + 1] = (char *)lua_tostring(L, -1);
  }
  argv[num_args + 1] = NULL;

  size_t inp_size = 0;
  char *inp;
  if (has_stdin)
    inp = (char *)luaL_checklstring(L, 3, &inp_size);

  int stdin_pipe[2], stdout_pipe[2];
  pid_t childpid;

  if (pipe(stdin_pipe) == -1)
    return luaL_error(L, "Failed creating stdin pipe: %s (code: %d)",
                      strerror(errno), errno);
  if (pipe(stdout_pipe) == -1)
    return luaL_error(L, "Failed creating stdout pipe: %s (code: %d)",
                      strerror(errno), errno);

  syslog(LOG_DEBUG, "Forking");

  if ((childpid = fork()) == -1) {
    return luaL_error(L, "Failed forking: %s (code: %d)", strerror(errno),
                      errno);
  }

  if (childpid == 0) {
    close(stdin_pipe[1]);
    close(stdout_pipe[0]);

    if (dup2(stdin_pipe[0], 0) == -1) {
      fprintf(stderr, "Failed duplicating stdin pipe: %s (code: %d)",
              strerror(errno), errno);
      exit(1);
    }
    if (dup2(stdout_pipe[1], 1) == -1) {
      fprintf(stderr, "Failed duplicating stdout pipe: %s (code: %d)",
              strerror(errno), errno);
      exit(1);
    }

    if (execvp(cmd, argv) == -1) {
      fprintf(stderr, "Failed executing %s: %s (code: %d)", cmd,
              strerror(errno), errno);
      exit(1);
    }
  }

  syslog(LOG_DEBUG, "Started child process %d", childpid);

  close(stdin_pipe[0]);
  close(stdout_pipe[1]);

  if (inp_size) {
    write(stdin_pipe[1], inp, inp_size);
    close(stdin_pipe[1]);
  }

  syslog(LOG_DEBUG, "Reading from stdout");
  int output_size = 0;
  unsigned char *output = read_fd(L, stdout_pipe[0], &output_size);
  if (output == NULL)
    return lua_error(L);

  int status;
  if (waitpid(childpid, &status, 0) == -1)
    return luaL_error(L, "Process failed: %s (code: %d)", strerror(errno),
                      errno);

  syslog(LOG_DEBUG, "Child process exited %d", status);

  if (status)
    return luaL_error(L, "Process exited with status %d", status);

  lua_pushlstring(L, (const char *)output, output_size);
  lua_pushinteger(L, output_size);

  return 2;
}

static int lua_post_request(lua_State *L) {
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *headers = 0;

  const char *url = luaL_checkstring(L, 1);
  const char *body = luaL_checkstring(L, 3);

  syslog(LOG_DEBUG, "Sending POST request to %s", url);

  curl = curl_easy_init();
  if (!curl) {
    lua_pushfstring(L, "Failed creating request: %s (code: %d)",
                    strerror(errno), errno);
    res = CURLE_OBSOLETE;
    goto cleanup;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

  int num_headers = luaL_len(L, 2);
  for (int i = 1; i <= num_headers; i++) {
    lua_pushinteger(L, i);
    lua_gettable(L, 2);
    headers = curl_slist_append(headers, lua_tostring(L, -1));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    lua_pushfstring(L, "Failed sending request: %s", curl_easy_strerror(res));
    goto cleanup;
  }

cleanup:
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (res != CURLE_OK)
    return lua_error(L);

  return 1;
}

static const struct luaL_Reg lua_lib[] = {{"query", lua_query},
                                          {"execute", lua_execute},
                                          {"render", lua_render},
                                          {"post", lua_post_request},
                                          {"base64_encode", lua_base64_encode},
                                          {NULL, NULL}};

static int render_lua_resource(sqlite3 *db, struct resource *res,
                               struct kreq *req, const int status) {
  syslog(LOG_DEBUG, "Rendering Lua resource %s", res->slug);

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

  if (req->scheme == KSCHEME_HTTPS) {
    pushtablestring(L, "scheme", (char *)"https");
  } else {
    pushtablestring(L, "scheme", (char *)"http");
  }
  pushtablestring(L, "host", req->host);
  pushtablestring(L, "method", (char *)"GET");
  pushtablestring(L, "root", req->pname);
  pushtablestring(L, "path", req->fullpath);
  pushtablestring(L, "remote", req->remote);
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
  if (req->reqsz > 0) {
    for (size_t i = 0; i < req->reqsz; i++) {
      pushtablestring(L, req->reqs[i].key, req->reqs[i].val);
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
                                struct kreq *req, const int status) {
  if (res->tmpl == NULL) {
    return 0;
  }

  syslog(LOG_DEBUG, "Rendering HTML resource %s", res->slug);

  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  lua_pushlightuserdata(L, db);
  lua_pushstring(L, res->tmpl);
  lua_createtable(L, 0, 10);
  pushtableint(L, "status", (int)status);
  pushtablestring(L, "reqpath", req->fullpath);
  pushtablestring(L, "baseurl", res->baseurl);
  pushtablestring(L, "slug", res->slug);
  pushtablestring(L, "srcpath", res->srcpath);
  pushtablestring(L, "name", res->name);
  pushtablelstring(L, "content", res->content, res->size);
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

int render_resource(sqlite3 *db, struct resource *res, struct kreq *req,
                    enum khttp status) {
  if (strcmp(res->mime, "text/html") == 0) {
    return render_html_resource(db, res, req, status);
  } else if (strcmp(res->mime, "text/x-lua") == 0) {
    return render_lua_resource(db, res, req, status);
  }

  return 0;
}

void free_resource(struct resource *res) {
  syslog(LOG_DEBUG, "Freeing resource slug");
  sqlite3_free(res->slug);
  syslog(LOG_DEBUG, "Freeing resource srcpath");
  sqlite3_free(res->srcpath);
  syslog(LOG_DEBUG, "Freeing resource name");
  sqlite3_free(res->name);
  syslog(LOG_DEBUG, "Freeing resource mime");
  sqlite3_free(res->mime);
  syslog(LOG_DEBUG, "Freeing resource content");
  sqlite3_free(res->content);
  syslog(LOG_DEBUG, "Freeing resource tmpl");
  sqlite3_free(res->tmpl);
  syslog(LOG_DEBUG, "Freeing resource moved_to");
  sqlite3_free(res->moved_to);
  syslog(LOG_DEBUG, "Freeing resource ctime");
  sqlite3_free(res->ctime);
  syslog(LOG_DEBUG, "Freeing resource mtime");
  sqlite3_free(res->mtime);
  syslog(LOG_DEBUG, "Freeing resource tags");
  sqlite3_free(res->tags);
  syslog(LOG_DEBUG, "Freeing resource baseurl");
  sqlite3_free(res->baseurl);
  syslog(LOG_DEBUG, "Done freeing resource");
}
