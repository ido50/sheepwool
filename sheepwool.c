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
#include <sys/stat.h>
#include <time.h>

#include <kcgi.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <magic.h>
#include <sass.h>
#include <sqlite3.h>

#include "deps/strsplit/strsplit.h"
#include "etlua.h"
#include "sheepwool.h"

int connect(struct database *db, char *dbpath, bool read_only) {
  int rc =
      sqlite3_open_v2(dbpath, &db->conn,
                      read_only ? SQLITE_OPEN_READONLY
                                : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      NULL);
  if (rc) {
    db->err_code = rc;
    db->err_msg = sqlite3_errmsg(db->conn);
    sqlite3_close(db->conn);
    return rc;
  }

  if (read_only) {
    rc = init_ro(db);
  } else {
    rc = init_rw(db);
  }
  if (rc) {
    db->err_code = rc;
    db->err_msg = sqlite3_errmsg(db->conn);
    sqlite3_close(db->conn);
    return rc;
  }

  db->err_code = 0;
  db->err_msg = NULL;

  return SQLITE_OK;
}

int disconnect(struct database *db) { return sqlite3_close(db->conn); }

struct bind_param bind(int type, int int_value, double double_value,
                       char *char_value, unsigned long size) {
  struct bind_param p;
  p.type = type;
  p.int_value = int_value;
  p.double_value = double_value;
  p.char_value = char_value;
  p.size = size;
  return p;
}

static int bind_params(sqlite3_stmt *stmt, int num_params,
                       struct bind_param params[]) {
  if (num_params == 0)
    return 0;

  for (int i = 0; i < num_params; i++) {
    int rc = 0;

    struct bind_param bp = params[i];
    switch (bp.type) {
    case SQLITE_INTEGER:
      rc = sqlite3_bind_int(stmt, i + 1, bp.int_value);
      break;
    case SQLITE_FLOAT:
      rc = sqlite3_bind_double(stmt, i + 1, bp.double_value);
      break;
    case SQLITE_TEXT:
      rc = sqlite3_bind_text(stmt, i + 1, bp.char_value, -1, NULL);
      break;
    case SQLITE_BLOB:
      rc = sqlite3_bind_blob(stmt, i + 1, bp.char_value, bp.size, NULL);
      break;
    case SQLITE_NULL:
      rc = sqlite3_bind_null(stmt, i + 1);
      break;
    }

    if (rc) {
      return rc;
    }
  }

  return 0;
}

static sqlite3_stmt *prepare_va(struct database *db, const char *sql,
                                va_list *params) {
  sqlite3_stmt *stmt;

  int rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
  if (rc) {
    db->err_code = rc;
    db->err_msg = sqlite3_errmsg(db->conn);
    sqlite3_finalize(stmt);
    return NULL;
  }

  int num_params = sqlite3_bind_parameter_count(stmt);

  struct bind_param params_array[num_params];

  for (int i = 0; i < num_params; i++) {
    struct bind_param bp = va_arg(*params, struct bind_param);
    params_array[i] = bp;
  }
  va_end(*params);

  rc = bind_params(stmt, num_params, params_array);
  if (rc) {
    db->err_code = rc;
    db->err_msg = sqlite3_errmsg(db->conn);
    sqlite3_finalize(stmt);
    return NULL;
  }

  return stmt;
}

sqlite3_stmt *prepare(struct database *db, const char *sql, ...) {
  va_list params;
  va_start(params, sql);

  return prepare_va(db, sql, &params);
}

int execute(struct database *db, const char *sql, ...) {
  va_list params;
  va_start(params, sql);

  sqlite3_stmt *stmt = prepare_va(db, sql, &params);
  if (stmt == NULL) {
    return db->err_code;
  }

  int rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
    db->err_code = rc;
    db->err_msg = sqlite3_errmsg(db->conn);
    sqlite3_finalize(stmt);
    return rc;
  }

  sqlite3_finalize(stmt);

  return SQLITE_OK;
}

int init_rw(struct database *db) {
  const char *stmts[] = {
      "PRAGMA application_id = 'sheepwool'",
      "PRAGMA secure_delete = 1",
      "PRAGMA encoding = 'UTF-8'",
      "PRAGMA foreign_keys = true",
      "PRAGMA journal_mode = WAL",
      "BEGIN",
      "CREATE TABLE IF NOT EXISTS vars ("
      "    key             TEXT PRIMARY KEY,"
      "    value           ANY NOT NULL"
      ") STRICT",
      "CREATE TABLE IF NOT EXISTS resources ("
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
      ") STRICT",
      "CREATE TABLE IF NOT EXISTS tags ("
      "    slug      TEXT NOT NULL,"
      "    tag       TEXT NOT NULL,"
      "    PRIMARY KEY (slug, tag)"
      ") STRICT",
      "CREATE INDEX IF NOT EXISTS resource_status ON resources(status)",
      "COMMIT"};

  for (int i = 0; i < 11; i++) {
    int rc = execute(db, stmts[i]);
    if (rc != SQLITE_OK) {
      printf("Init statement %d failed: %s\n", i, db->err_msg);
      if (i > 5) {
        execute(db, "ROLLBACK");
      }
      return rc;
    }
  }

  return SQLITE_OK;
}

int init_ro(struct database *db) {
  const char *stmts[] = {
      "PRAGMA encoding = 'UTF-8'",
      "PRAGMA foreign_keys = true",
      "PRAGMA journal_mode = WAL",
  };

  for (int i = 0; i < 3; i++) {
    int rc = execute(db, stmts[i]);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }

  return SQLITE_OK;
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

  int blob_size = sqlite3_column_bytes(stmt, col_num);
  char *dest = sqlite3_malloc(blob_size);
  memcpy(dest, sqlite3_column_blob(stmt, col_num), blob_size);

  return dest;
}

static void dumpstack(lua_State *L) {
  int top = lua_gettop(L);
  printf("Stack size is %d\n", top);
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

static char *mime_type(char *path) {
  magic_t cookie = magic_open(MAGIC_MIME_TYPE);
  if (cookie == NULL) {
    printf("libmagic failed opening cookie\n");
    return NULL;
  }

  if (magic_load(cookie, NULL) != 0) {
    printf("libmagic failed loading DB: %s\n", magic_error(cookie));
    magic_close(cookie);
    return NULL;
  }

  const char *mime = magic_file(cookie, path);
  if (mime == NULL) {
    printf("libmagic failed parsing file: %s\n", magic_error(cookie));
    magic_close(cookie);
    return NULL;
  }

  char *result = sqlite3_mprintf("%s", mime);

  magic_close(cookie);

  return result;
}

static char *parse_time(time_t time) {
  size_t size = sizeof("2022-01-01T00:00:00");
  char *target = sqlite3_malloc(size);
  strftime(target, size, "%Y-%m-%dT%H:%M:%S", gmtime(&time));
  return target;
}

static int parse_html(lua_State *L, struct resource *res, char *abspath) {
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
        strsplit(value, res->tags, ", ");
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
  struct Sass_Options *options = sass_make_options();
  sass_option_set_output_style(options, SASS_STYLE_COMPRESSED);
  sass_option_set_precision(options, 10);

  struct Sass_Data_Context *ctx =
      sass_make_data_context(strndup(res->content, res->size));
  struct Sass_Context *ctx_out = sass_data_context_get_context(ctx);
  sass_data_context_set_options(ctx, options);
  sass_compile_data_context(ctx);

  if (sass_context_get_error_status(ctx_out)) {
    const char *error_message = sass_context_get_error_message(ctx_out);
    if (error_message) {
      fprintf(stderr, "Failed parsing SCSS: %s\n", error_message);
    } else {
      fprintf(stderr, "Failed parsing SCSS: no error message available.\n");
    }
    sass_delete_data_context(ctx);
    return 1;
  }

  res->content = sqlite3_mprintf("%s", sass_context_get_output_string(ctx_out));
  res->slug = replace(L, res->slug, "%.scss$", ".css");
  res->mime = sqlite3_mprintf("text/css");
  res->size = strlen(res->content);

  sass_delete_data_context(ctx);

  return 0;
}

static int import_file(lua_State *L, struct database *db, char *root,
                       char *abspath, char *relpath, struct stat fstat) {
  struct resource res;
  res.srcpath = sqlite3_mprintf("%s", relpath);
  res.slug = sqlite3_mprintf("%s", relpath);
  res.mime = mime_type(abspath);
  res.baseurl = NULL;
  res.name = sqlite3_mprintf("%s", basename(relpath));
  res.status = 0;
  res.tmpl = NULL;
  res.moved_to = NULL;
  res.content = NULL;
  res.ctime = parse_time(fstat.st_mtime);
  res.mtime = parse_time(fstat.st_mtime);
  for (int i = 0; i < MAX_TAGS; i++) {
    res.tags[i] = NULL;
  }

  printf("Importing file %s... ", relpath);

  FILE *fd = fopen(abspath, "rb");
  if (fd == 0) {
    perror("Failed opening file");
    free_resource(&res);
    return errno;
  }

  res.content = sqlite3_malloc(fstat.st_size + 1);
  if (res.content == 0) {
    perror("Failed allocating memory for file");
    free_resource(&res);
    return errno;
  }

  if (fstat.st_size > 0 && fread(res.content, fstat.st_size, 1, fd) != 1) {
    perror("Failed reading file");
    free_resource(&res);
    return errno;
  }

  fclose(fd);

  res.size = fstat.st_size;

  if (match(L, abspath, "%.html$")) {
    parse_html(L, &res, abspath);
  } else if (match(L, abspath, "%.scss$")) {
    parse_scss(L, &res, abspath);
  } else if (match(L, abspath, "%.lua$")) {
    sqlite3_free(res.mime);
    res.mime = sqlite3_mprintf("text/x-lua");
    res.slug = replace(L, res.slug, "%.lua$", "");
  }

  printf("%s... ", res.slug);

  if (match(L, res.slug, "/index$")) {
    if (!match(L, res.slug, "^/templates/index$")) {
      res.slug = replace(L, res.slug, "/index$", "");
      if (strcmp(res.slug, "") == 0) {
        res.slug = sqlite3_mprintf("/");
      }
    }
  }

  int rc = execute(db, "BEGIN");
  if (rc != SQLITE_OK) {
    printf("Failed starting transaction: %s\n", db->err_msg);
    free_resource(&res);
    return db->err_code;
  }

  rc = execute(
      db,
      "INSERT OR REPLACE INTO resources "
      "(slug, srcpath, mime, name, status, content, size, template, moved_to, "
      " ctime, mtime) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      bind(SQLITE_TEXT, 0, 0, res.slug, 0),
      bind(SQLITE_TEXT, 0, 0, res.srcpath, 0),
      bind(SQLITE_TEXT, 0, 0, res.mime, 0),
      bind(SQLITE_TEXT, 0, 0, res.name, 0),
      bind(SQLITE_INTEGER, res.status, 0, NULL, 0),
      bind(SQLITE_BLOB, 0, 0, res.content, res.size),
      bind(SQLITE_INTEGER, res.size, 0, NULL, 0),
      bind(SQLITE_TEXT, 0, 0, res.tmpl, 0),
      bind(SQLITE_TEXT, 0, 0, res.moved_to, 0),
      bind(SQLITE_TEXT, 0, 0, res.ctime, 0),
      bind(SQLITE_TEXT, 0, 0, res.mtime, 0));
  if (rc != SQLITE_OK) {
    printf("Failed inserting to database: %s\n", db->err_msg);
    execute(db, "ROLLBACK");
    free_resource(&res);
    return rc;
  }

  rc = execute(db, "DELETE FROM tags WHERE slug=?",
               bind(SQLITE_TEXT, 0, 0, res.slug, 0));
  if (rc != SQLITE_OK) {
    printf("Failed removing existing tags: %s (%d)\n", db->err_msg,
           db->err_code);
    execute(db, "ROLLBACK");
    free_resource(&res);
    return rc;
  }

  for (int i = 0; i < MAX_TAGS; i++) {
    if (res.tags[i] == NULL) {
      break;
    }

    rc = execute(db, "INSERT INTO tags VALUES (?, ?)",
                 bind(SQLITE_TEXT, 0, 0, res.slug, 0),
                 bind(SQLITE_TEXT, 0, 0, res.tags[i], 0));
    if (rc != SQLITE_OK) {
      printf("Failed inserting tag %d (%s): %s (%d)\n", i, res.tags[i],
             db->err_msg, db->err_code);
      execute(db, "ROLLBACK");
      free_resource(&res);
      return rc;
    }
  }

  rc = execute(db, "COMMIT");
  if (rc != SQLITE_OK) {
    printf("Failed committing transaction: %s\n", db->err_msg);
    execute(db, "ROLLBACK");
    free_resource(&res);
    return rc;
  }

  printf("imported as %s at %s\n", res.mime, res.slug);

  free_resource(&res);

  return 0;
}

static int build_dir(lua_State *L, struct database *db, char *root,
                     char *relpath) {
  char *abspath;
  if (relpath == NULL) {
    abspath = sqlite3_mprintf("%s", root);
  } else {
    abspath = sqlite3_mprintf("%s/%s", root, relpath);
  }

  printf("Working on directory %s\n", relpath);

  DIR *dir = opendir(abspath);
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;

    char *absfilepath = sqlite3_mprintf("%s/%s", abspath, entry->d_name);
    char *relfilepath = sqlite3_mprintf("%s/%s", relpath, entry->d_name);

    struct stat fstat;
    int rc = lstat(absfilepath, &fstat);
    if (rc) {
      perror("Failed running lstat");
      sqlite3_free(relfilepath);
      sqlite3_free(absfilepath);
      closedir(dir);
      sqlite3_free(abspath);
      return rc;
    }

    if (S_ISDIR(fstat.st_mode) || entry->d_type == DT_DIR) {
      lua_pop(L, lua_gettop(L));
      rc = build_dir(L, db, root, relfilepath);
      if (rc) {
        perror("Failed building directory");
        sqlite3_free(relfilepath);
        sqlite3_free(absfilepath);
        closedir(dir);
        sqlite3_free(abspath);
        return rc;
      }
    } else if (S_ISREG(fstat.st_mode) || entry->d_type == DT_REG) {
      lua_pop(L, lua_gettop(L));
      rc = import_file(L, db, root, absfilepath, relfilepath, fstat);
      if (rc) {
        perror("Failed importing file");
        sqlite3_free(relfilepath);
        sqlite3_free(absfilepath);
        closedir(dir);
        sqlite3_free(abspath);
        return rc;
      }
    }

    sqlite3_free(relfilepath);
    sqlite3_free(absfilepath);
  }

  closedir(dir);
  sqlite3_free(abspath);
  return 0;
}

int fsbuild(struct database *db, char *root) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  printf("Building database from %s\n", root);
  int ret = build_dir(L, db, root, NULL);
  lua_close(L);

  return ret;
}

int load_resource(struct database *db, struct resource *res, char *slug) {
  sqlite3_stmt *stmt = prepare(
      db,
      "    SELECT r.slug, r.srcpath, r.name, r.mime, r.status, r.content,"
      "           r.size, r.template, r.moved_to, r.ctime, r.mtime,"
      "           group_concat(t.tag) AS tags"
      "      FROM resources r"
      " LEFT JOIN tags t ON t.slug = r.slug"
      "     WHERE r.slug=?"
      "  GROUP BY r.slug",
      bind(SQLITE_TEXT, 0, 0, slug, 0));
  if (stmt == NULL) {
    printf("Prepare failed: %s\n", db->err_msg);
    return SQLITE_ERROR;
  }

  int rc = sqlite3_step(stmt);
  if (rc != SQLITE_ROW) {
    if (rc != SQLITE_DONE) {
      db->err_code = rc;
      db->err_msg = sqlite3_errmsg(db->conn);
    }

    sqlite3_finalize(stmt);
    return SQLITE_NOTFOUND;
  }

  res->slug = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 0));

  if (strcmp(res->slug, "") == 0) {
    sqlite3_finalize(stmt);
    return SQLITE_NOTFOUND;
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
  char *tags = get_nullable_text(stmt, 11);
  size_t num_tags = 0;
  if (tags != NULL) {
    num_tags = strsplit(tags, res->tags, ",");
  }
  for (int i = num_tags; i < MAX_TAGS; i++) {
    res->tags[i] = NULL;
  }

  sqlite3_finalize(stmt);

  return SQLITE_OK;
}

static void pushtablestring(lua_State *L, const char *key, char *value) {
  lua_pushstring(L, key);
  lua_pushstring(L, value);
  lua_settable(L, -3);
}

static int open_etlua(lua_State *L) {
  if (luaL_loadstring(L, (const char *)etlua) != LUA_OK) {
    return lua_error(L);
  }
  lua_call(L, 0, 1);
  return 1;
}

static int lua_query(lua_State *L) {
  if (!lua_islightuserdata(L, 1)) {
    return luaL_argerror(L, 1, "must be a database connection");
  }

  struct database *db = (struct database *)lua_touserdata(L, 1);
  const char *sql = luaL_checkstring(L, 2);

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
  if (rc) {
    lua_pushfstring(L, "prepare failed: %s", sqlite3_errmsg(db->conn));
    sqlite3_finalize(stmt);
    return lua_error(L);
  }

  int num_params = sqlite3_bind_parameter_count(stmt);

  struct bind_param params[num_params];

  if (num_params > 0 && num_params < MAX_PARAMS) {
    for (int i = 0; i < num_params; i++) {
      int si = i + 4;
      switch (lua_type(L, si)) {
      case LUA_TSTRING:
        params[i] = bind(SQLITE_TEXT, 0, 0, (char *)lua_tostring(L, si), 0);
        break;
      case LUA_TBOOLEAN:
        params[i] = bind(SQLITE_INTEGER, lua_toboolean(L, si), 0, NULL, 0);
        break;
      case LUA_TNUMBER:
        if (lua_isinteger(L, si)) {
          params[i] = bind(SQLITE_INTEGER, lua_tointeger(L, si), 0, NULL, 0);
          break;
        } else {
          params[i] = bind(SQLITE_FLOAT, 0, lua_tonumber(L, si), NULL, 0);
          break;
        }
      case LUA_TNIL:
        params[i] = bind(SQLITE_NULL, 0, 0, NULL, 0);
        break;
      }
    }
  }

  rc = bind_params(stmt, num_params, params);
  if (rc) {
    lua_pushfstring(L, "bind failed: %s", sqlite3_errmsg(db->conn));
    sqlite3_finalize(stmt);
    return lua_error(L);
  }

  int num_rows = 0;

  lua_newtable(L);

  while (true) {
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
      break;
    } else if (rc != SQLITE_ROW) {
      sqlite3_finalize(stmt);
      return luaL_error(L, "execute failed: %s", sqlite3_errmsg(db->conn));
    }

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
        sqlite3_finalize(stmt);
        return luaL_error(L, "unknown column return type for %d", i);
      }
      lua_settable(L, -3);
    }
    lua_settable(L, -3);
  }

  sqlite3_finalize(stmt);

  return 1;
}

static int lua_render(lua_State *L) {
  struct database *db = (struct database *)lua_touserdata(L, 1);
  char *tmpl_name = sqlite3_mprintf("%s", lua_tostring(L, 2));

  // stack: [db, slug, context]

  luaL_requiref(L, "etlua", open_etlua, 0);
  // stack: [db, slug, context, etlua]

  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db->conn,
                              "SELECT content, size, template"
                              "  FROM resources"
                              " WHERE slug = ?",
                              -1, &stmt, NULL);
  if (rc) {
    lua_pushfstring(L, "Failed preparing template statement: %s",
                    sqlite3_errmsg(db->conn));
    sqlite3_finalize(stmt);
    return lua_error(L);
  }

  while (true) {
    if (lua_getfield(L, 4, "render") != LUA_TFUNCTION) {
      return luaL_error(L, "failed getting render function: got %s",
                        lua_typename(L, lua_type(L, -1)));
    }
    // stack: [db, slug, context, etlua, render]

    rc = sqlite3_bind_text(stmt, 1, tmpl_name, -1, NULL);
    if (rc) {
      lua_pushfstring(L, "Failed binding template slug: %s",
                      sqlite3_errmsg(db->conn));
      sqlite3_finalize(stmt);
      return lua_error(L);
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
      lua_pushfstring(L, "Failed loading template: %s",
                      sqlite3_errmsg(db->conn));
      sqlite3_finalize(stmt);
      return lua_error(L);
    }

    char *tmpl = get_nullable_blob(stmt, 0);
    if (tmpl == NULL) {
      sqlite3_finalize(stmt);
      return luaL_error(L, "failed getting template: content is NULL");
    }

    int size = sqlite3_column_int(stmt, 1);

    sqlite3_free(tmpl_name);
    tmpl_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 2));

    lua_pushlstring(L, tmpl, size);
    // stack: [db, slug, context, etlua, render, template]

    lua_pushnil(L);
    lua_copy(L, 3, 7);
    // stack: [db, slug, context, etlua, render, template, context]

    if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
      sqlite3_finalize(stmt);
      return luaL_error(L, "failed rendering template: %s",
                        lua_tostring(L, -1));
    }
    // stack: [db, slug, context, etlua, output]

    if (strcmp(tmpl_name, "") != 0) {
      lua_setfield(L, 3, "content");
      sqlite3_reset(stmt);
      continue;
      // stack: [db, slug, context, etlua]
    }

    break;
  }

  sqlite3_free(tmpl_name);
  sqlite3_finalize(stmt);

  return 1;
}

static const struct luaL_Reg lua_lib[] = {
    {"query", lua_query}, {"render", lua_render}, {NULL, NULL}};

static int render_lua_resource(struct database *db, struct resource *res,
                               struct kreq *req) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  char content[res->size + 1];
  strlcpy(content, res->content, res->size + 1);
  int rc = luaL_dostring(L, content);
  if (rc != LUA_OK) {
    fprintf(stderr, "Failed evaluating lua code: %s\n", lua_tostring(L, -1));
    lua_close(L);
    return 1;
  }

  if (lua_getglobal(L, "render") != LUA_TFUNCTION) {
    fprintf(stderr, "Failed getting resource's render function, it is %s\n",
            lua_typename(L, lua_type(L, -1)));
    lua_close(L);
    return 1;
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

  lua_pushliteral(L, "params");
  lua_newtable(L);
  if (req->fieldsz > 0) {
    for (size_t i = 0; i < req->fieldsz; i++) {
      pushtablestring(L, req->fields[i].key, req->fields[i].val);
    }
  }
  lua_settable(L, -3);

  lua_pushliteral(L, "headers");
  lua_newtable(L);
  if (req->reqsz > 0) {
    for (size_t i = 0; i < req->reqsz; i++) {
      pushtablestring(L, req->reqs[i].key, req->reqs[i].val);
    }
  }
  lua_settable(L, -3);
  // stack: [resource_lua, render, sheepwool, db, context]

  if (lua_pcall(L, 3, 2, 0) != LUA_OK) {
    fprintf(stderr, "Failed rendering: %s\n", lua_tostring(L, -1));
    lua_close(L);
    return 1;
  }
  // stack: [resource_lua, mime, content]

  res->mime = sqlite3_mprintf("%s", lua_tostring(L, -2));
  size_t size = 0;
  res->content = sqlite3_mprintf("%s", lua_tolstring(L, -1, &size));
  res->size = size;

  lua_close(L);

  return 0;
}

static int render_html_resource(struct database *db, struct resource *res,
                                struct kreq *req) {
  if (res->tmpl == NULL) {
    return 0;
  }

  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  lua_pushlightuserdata(L, db);
  lua_pushstring(L, res->tmpl);
  lua_createtable(L, 0, 8);
  pushtablestring(L, "baseurl", res->baseurl);
  pushtablestring(L, "slug", res->slug);
  pushtablestring(L, "srcpath", res->srcpath);
  pushtablestring(L, "name", res->name);
  pushtablestring(L, "content", res->content);
  pushtablestring(L, "ctime", res->ctime);
  pushtablestring(L, "mtime", res->mtime);
  lua_pushliteral(L, "tags");
  lua_createtable(L, MAX_TAGS, 0);
  for (int i = 0; i < MAX_TAGS; i++) {
    if (res->tags[i] == NULL) {
      break;
    }

    lua_pushinteger(L, i + 1);
    lua_pushstring(L, res->tags[i]);
    lua_settable(L, -3);
  }
  lua_settable(L, -3);
  // stack: [db, template_name, context]

  lua_render(L);

  size_t size = 0;
  res->content = sqlite3_mprintf("%s", lua_tolstring(L, -1, &size));
  res->size = size;

  lua_close(L);

  return 0;
}

int render_resource(struct database *db, struct resource *res,
                    struct kreq *req) {
  if (strcmp(res->mime, "text/html") == 0) {
    return render_html_resource(db, res, req);
  } else if (strcmp(res->mime, "text/x-lua") == 0) {
    return render_lua_resource(db, res, req);
  }

  return 0;
}

void free_resource(struct resource *res) {
  /*printf("Freeing resource %s\n", res->slug);*/
  /*printf("\tFreeing slug\n");*/
  sqlite3_free(res->slug);
  /*printf("\tFreeing srcpath\n");*/
  sqlite3_free(res->srcpath);
  /*printf("\tFreeing name\n");*/
  sqlite3_free(res->name);
  /*printf("\tFreeing mime\n");*/
  sqlite3_free(res->mime);
  /*printf("\tFreeing content\n");*/
  sqlite3_free(res->content);
  /*printf("\tFreeing tmpl\n");*/
  sqlite3_free(res->tmpl);
  /*printf("\tFreeing moved_to\n");*/
  sqlite3_free(res->moved_to);
  /*printf("\tFreeing ctime\n");*/
  sqlite3_free(res->ctime);
  /*printf("\tFreeing mtime\n");*/
  sqlite3_free(res->mtime);
  for (int i = 0; i < MAX_TAGS; i++) {
    if (res->tags[i] == NULL) {
      break;
    }
    /*printf("\tFreeing tags[%d]: %s\n", i, res->tags[i]);*/
    sqlite3_free(res->tags[i]);
  }
  /*printf("\tFreeing baseurl\n");*/
  sqlite3_free(res->baseurl);
}
