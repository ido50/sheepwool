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

#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>   // for errno, EAGAIN
#include <lauxlib.h> // for luaL_error, luaL_checklstring, luaL_len
#include <libgen.h>  //for basename
#include <lua.h>
#include <magic.h>
#include <microhttpd.h>
#include <sass/base.h>
#include <sass/context.h>
#include <sqlite3.h>
#include <stdarg.h>   // for va_arg, va_end, va_start
#include <stdbool.h>  // for bool, true, false
#include <stdio.h>    // for fprintf, printf, stderr, snprintf, fclose
#include <stdlib.h>   // for malloc, free, exit, realloc
#include <string.h>   // for strerror, strcmp, strdup, strlen, memcpy
#include <sys/stat.h> // for stat, lstat, st_ctime, st_mtime
#include <sys/wait.h> // for waitpid
#include <tidy.h>
#include <tidybuffio.h>
#include <tidyenum.h>
#include <tidyplatform.h>
#include <unistd.h> // for close, dup2, pipe, access, execvp, fork

#if HAVE_B64_NTOP
#include <netinet/in.h>
#include <resolv.h> // for b64_ntop, b64_pton
#endif

#include "database.h"
#include "etlua.c"
#include "library.h"

enum FileType {
  OTHER = 0,
  LUA = 1,
  HTML = 2,
  SCSS = 3,
};

static char *get_basename(char *path) {
  char *dup_path = strdup(path);
  char *base_name = strdup(basename(dup_path));
  free(dup_path);
  return base_name;
}

// str_starts_with is taken from:
// https://github.com/stephenmathieson/str-starts-with.c
// Copyright (c) 2013 Stephen Mathieson
// MIT licensed
bool str_starts_with(const char *str, const char *start) {
  for (;; str++, start++)
    if (!*start)
      return true;
    else if (*str != *start)
      return false;
}

char *get_abspath(const char *host, bool is_localhost, const char *path) {
  int len_prefix = 2; // length of ./ prefix
  int len_path = strlen(path);
  int len = len_prefix + len_path + 1; // 1 for NULL terminator

  // if path has a trailing slash, remove it
  if (len_path > 1 && path[len_path - 1] == '/')
    len -= 1;

  char *buffer = NULL;
  int ret = 0;

  if (is_localhost) {
    // remove heading slash
    if (path[0] == '/') {
      len -= 1;
      path = path + 1;
    }

    buffer = malloc((size_t)((unsigned)len));
    ret = snprintf(buffer, len, "./%s", path);
  } else {
    // account for the host
    len += strlen(host);

    // we need a heading slash when we have a host
    if (path[0] != '/')
      len++;

    buffer = malloc(len);
    ret = path[0] == '/' ? snprintf(buffer, len, "./%s%s", host, path)
                         : snprintf(buffer, len, "./%s/%s", host, path);
  }

  if (ret < 0) {
    free(buffer);
    return NULL;
  }

  return buffer;
}

static char *dup_and_push(char *source, const char *addition) {
  char *dup = strdup(source);
  if (source[strlen(source) - 1] == '/') {
    dup = realloc(dup, strlen(dup) + strlen(addition));
    strcat(dup, addition + 1);
  } else {
    dup = realloc(dup, strlen(dup) + strlen(addition) + 1);
    strcat(dup, addition);
  }
  return dup;
}

static char *slugify(lua_State *L, char *orig) {
  return replace(L, (char *)orig, "%.html$", "");
}

char *parse_time(time_t time) {
  size_t size = sizeof("2022-01-01T00:00:00");
  char *target = malloc(size);
  strftime(target, size, "%Y-%m-%dT%H:%M:%S", gmtime(&time));
  return target;
}

static const char *gettablestring(lua_State *L, int table_index,
                                  const char *key) {
  lua_pushstring(L, key);
  if (lua_gettable(L, table_index) == LUA_TSTRING) {
    const char *val = lua_tostring(L, -1);
    lua_pop(L, 1);
    return val;
  }

  lua_pop(L, 1);

  return NULL;
}

void pushtableliteral(lua_State *L, const char *key, const char *value) {
  lua_pushstring(L, key);
  lua_pushstring(L, value);
  lua_settable(L, -3);
}

void pushtablestring(lua_State *L, const char *key, char *value) {
  lua_pushstring(L, key);
  lua_pushstring(L, value);
  lua_settable(L, -3);
}

void pushtablelstring(lua_State *L, const char *key, char *value, int valsize) {
  lua_pushstring(L, key);
  lua_pushlstring(L, value, valsize);
  lua_settable(L, -3);
}

void pushtableint(lua_State *L, const char *key, int value) {
  lua_pushstring(L, key);
  lua_pushinteger(L, value);
  lua_settable(L, -3);
}

void pushtableclosure(lua_State *L, const char *name, lua_CFunction fn, int n,
                      ...) {
  lua_pushstring(L, name);
  if (n > 0) {
    va_list upvalues;
    va_start(upvalues, n);
    for (int i = 0; i < n; i++) {
      lua_pushlightuserdata(L, va_arg(upvalues, void *));
    }
    va_end(upvalues);
  }
  lua_pushcclosure(L, fn, n);
  lua_settable(L, -3);
}

bool match(lua_State *L, char *str, const char *pattern) {
  lua_getglobal(L, "string");
  lua_getfield(L, -1, "match");
  lua_pushstring(L, str);
  lua_pushstring(L, pattern);

  bool matched = lua_pcall(L, 2, 1, 0) == LUA_OK && lua_isstring(L, -1);

  lua_pop(L, 2);

  return matched;
}

char *replace(lua_State *L, char *str, const char *pattern, const char *repl) {
  lua_getglobal(L, "string");
  lua_getfield(L, -1, "gsub");
  lua_pushstring(L, str);
  lua_pushstring(L, pattern);
  lua_pushstring(L, repl);

  char *result = NULL;
  if (lua_pcall(L, 3, 1, 0) == LUA_OK && lua_isstring(L, -1)) {
    result = strdup(lua_tostring(L, -1));
  }

  lua_pop(L, 2);

  return result;
}

void dumpstack(lua_State *L) {
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

static int open_etlua(lua_State *L) {
  if (luaL_loadstring(L, (const char *)etlua) != LUA_OK) {
    return lua_error(L);
  }
  lua_call(L, 0, 1);
  return 1;
}

static char *tidy_html(const char *input) {
  TidyBuffer buf = {0};
  char *output = NULL;
  int rc = -1;

  TidyDoc tdoc = tidyCreate();

  Bool ok = tidyOptSetBool(tdoc, TidyHtmlOut, yes);
  if (!ok)
    goto cleanup;

  ok = tidyOptSetBool(tdoc, TidyHideComments, yes);
  if (!ok)
    goto cleanup;

  ok = tidyOptSetBool(tdoc, TidyDropEmptyElems, no);
  if (!ok)
    goto cleanup;

  ok = tidyOptSetBool(tdoc, TidyWrapLen, 120);
  if (!ok)
    goto cleanup;

  rc = tidyParseString(tdoc, input);

  if (rc >= 0)
    rc = tidyCleanAndRepair(tdoc);

  if (rc >= 0)
    rc = tidySaveBuffer(tdoc, &buf);

  if (rc >= 0) {
    output = strndup((const char *)buf.bp, buf.size);
  } else {
    output = strdup(input);
  }

cleanup:
  tidyBufFree(&buf);
  tidyRelease(tdoc);

  return output;
}

struct list_options {
  const char *ext;
  const char *tag;
};

int list_resources(lua_State *L) {
  struct connection_info *con_info =
      (struct connection_info *)lua_touserdata(L, lua_upvalueindex(1));

  // stack: [dirpath, opts]
  const char *dirpath = lua_tostring(L, 1);
  char *fullpath = get_abspath(con_info->host, con_info->is_localhost, dirpath);

  if (fullpath == NULL)
    return luaL_error(L, "Failed getting real path from %s", dirpath);

  if (lua_gettop(L) == 1)
    lua_newtable(L);

  struct list_options opts = {
      .ext = gettablestring(L, 2, "ext"),
      .tag = gettablestring(L, 2, "tag"),
  };

  int rc = 0;

  DIR *dir = opendir(fullpath);
  if (dir == NULL) {
    rc = 1;
    lua_pushfstring(L, "Failed opening directory %s: %s", fullpath,
                    strerror(errno));
    goto cleanup;
  }

  // create a table that will hold the results
  lua_newtable(L);

  // stack: [dirpath, opts, results]

  lua_getglobal(L, "string");

  // stack: [dirpath, opts, results, libstring]

  struct dirent *entry;
  int i = 0;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.' || entry->d_type != DT_REG)
      continue;

    if (opts.ext) {
      int fname_len = strlen(entry->d_name);
      int ext_len = strlen(opts.ext);
      if (fname_len < ext_len ||
          strcmp(entry->d_name + (fname_len - ext_len), opts.ext) != 0)
        continue;
    }

    char *filepath = NULL;
    FILE *fp = NULL;
    char *line = NULL;

    size_t filepath_size = strlen(fullpath) + strlen(entry->d_name) + 2;
    filepath = malloc(filepath_size);
    rc = snprintf(filepath, filepath_size, "%s/%s", fullpath, entry->d_name);
    if (rc == -1) {
      lua_pushfstring(L, "Failed joining path: %s", strerror(errno));
      goto loopcleanup;
    }

    struct stat fstat;
    rc = lstat(filepath, &fstat);
    if (rc) {
      lua_pushfstring(L, "Failed stat %s: %s", filepath, strerror(errno));
      goto loopcleanup;
    }

    lua_createtable(L, 0, 5);
    if (con_info->is_localhost) {
      size_t len = strlen(filepath) - 2; // -2 for ./
      char *slug = malloc(len + 1);
      memcpy(slug, filepath + 2, len);
      slug[len] = '\0';
      pushtablestring(L, "slug", slug);
      free(slug);
    } else {
      size_t host_len =
          strlen(con_info->host) + 3; // 2 for heading ./, 1 for trailing /
      size_t len = strlen(filepath) - host_len;
      char *slug = malloc(len + 1);
      memcpy(slug, filepath + host_len, len + 1);
      slug[len] = '\0';
      pushtablestring(L, "slug", slug);
      free(slug);
    }

    pushtablestring(L, "name", entry->d_name);
    char *ctime = parse_time(fstat.st_ctime);
    pushtablestring(L, "ctime", ctime);
    free(ctime);
    char *mtime = parse_time(fstat.st_mtime);
    pushtablestring(L, "mtime", mtime);
    free(mtime);
    lua_pushliteral(L, "tags");
    lua_newtable(L);
    lua_settable(L, -3);

    bool tag_found = false;

    // stack: [dirpath, ext, results, libstring, resource]

    if (match(L, entry->d_name, "%.html$")) {
      char *new_slug = slugify(L, (char *)gettablestring(L, 5, "slug"));
      pushtablestring(L, "slug", new_slug);
      free(new_slug);

      fp = fopen(filepath, "r");
      if (fp == NULL) {
        lua_pushfstring(L, "Failed opening file %s: %s", filepath,
                        strerror(errno));
        rc = errno;
        goto loopcleanup;
      }

      size_t len = 0;
      ssize_t read;

      while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\n")] = 0;

        lua_getfield(L, -2, "match");
        lua_pushstring(L, line);
        lua_pushstring(L, "<!%-%- ([^:]+): ([^>]+) %-%->");

        // stack: [dirpath, ext, results, libstring, resource, match, str, ptrn]

        if (lua_pcall(L, 2, 2, 0) != LUA_OK || lua_isnil(L, -1)) {
          lua_pop(L, 2);
          break;
        }

        // stack: [dirpath, ext, results, libstring, resource, key, val]
        const char *key = lua_tostring(L, -2);
        if (strcmp(key, "name") == 0 || strcmp(key, "ctime") == 0 ||
            strcmp(key, "mtime") == 0)
          lua_settable(L, -3);
        else if (strcmp(key, "tags") == 0) {
          char *tags = strdup(lua_tostring(L, -1));
          lua_pop(L, 1);
          lua_getfield(L, -2, "tags");
          char *tag = strtok(tags, ", ");
          int j = 0;
          while (tag) {
            lua_pushstring(L, tag);
            if (opts.tag && strcmp(tag, opts.tag) == 0)
              tag_found = true;
            lua_seti(L, -2, ++j);
            tag = strtok(NULL, ", ");
          }
          lua_settable(L, -3);
          free(tags);
        } else
          lua_pop(L, 2);

        // stack: [dirpath, ext, results, libstring, resource]
      }
    }

    if (opts.tag && !tag_found)
      lua_pop(L, 1);
    else
      lua_seti(L, 3, ++i);
    // stack: [dirpath, ext, results, libstring]

  loopcleanup:
    if (line)
      free(line);
    if (fp)
      fclose(fp);
    if (filepath)
      free(filepath);
    if (rc)
      goto cleanup;
  }

  // stack is now: [dirpath, ext, results, libstring]
  lua_pop(L, 1);
  lua_remove(L, 2);
  // stack is now: [results]

cleanup:
  if (dir)
    closedir(dir);
  free(fullpath);
  if (rc)
    return lua_error(L);

  return 1;
}

int render_tmpl(lua_State *L) {
  // stack: [path, context, [con_info]]

  struct connection_info *con_info =
      lua_gettop(L) == 3
          ? (struct connection_info *)lua_touserdata(L, 3)
          : (struct connection_info *)lua_touserdata(L, lua_upvalueindex(1));

  int etlua_at = lua_gettop(L) == 3 ? 4 : 3;

  luaL_requiref(L, "etlua", open_etlua, 0);
  // stack: [path, context, [con_info,] etlua]

  int rc = 0;

  while (true) {
    struct resource *tmpl = NULL;

    if (lua_getfield(L, etlua_at, "render") != LUA_TFUNCTION) {
      lua_pushfstring(L, "Failed getting render function: got %s",
                      lua_typename(L, lua_type(L, -1)));
      rc = 1;
      goto cleanup;
    }
    // stack: [path, context, [con_info,] etlua, render]

    if (lua_isstring(L, 1)) {
      const char *path = lua_tostring(L, 1);
      tmpl = load_resource(con_info, path);
      if (tmpl == NULL) {
        lua_pushfstring(L, "Failed loading template %s", path);
        rc = 1;
        goto cleanup;
      }

      lua_pushlstring(L, tmpl->content, tmpl->size);
    } else {
      lua_getfield(L, 2, "content");
    }
    // stack: [path, context, [con_info,] etlua, render, template]

    lua_pushnil(L);
    lua_copy(L, 2, etlua_at == 4 ? 7 : 6);
    // stack: [path, context, [con_info,] etlua, render, template, context]

    int rc = lua_pcall(L, 2, 1, 0);
    if (rc != LUA_OK) {
      lua_pushfstring(L, "Failed rendering template: %s", lua_tostring(L, -1));
      goto cleanup;
    }
    // stack: [path, context, [con_info,] etlua, output]

    if (lua_isnil(L, -1)) {
      lua_pushfstring(L, "Failed rendering template: got nil");
      rc = 1;
      goto cleanup;
    }

    if (tmpl != NULL && tmpl->tmpl != NULL) {
      lua_pushstring(L, tmpl->tmpl);
      lua_replace(L, 1);
      lua_setfield(L, 2, "content");
      free_resource(tmpl);
      continue;
      // stack: [path, context, [con_info,] etlua]
    }

    break;
  }

  lua_pushstring(L, lua_tostring(L, -1));
  lua_replace(L, -2);

cleanup:
  if (rc)
    return lua_error(L);

  return 1;
}

int base64enc(lua_State *L) {
  size_t inpsz;
  const char *inp = luaL_checklstring(L, 1, &inpsz);

  size_t outsz = ((inpsz + 2) / 3 * 4) + 1;
  char *out = malloc(outsz);
  if (b64_ntop((const unsigned char *)inp, inpsz, out, outsz) == -1) {
    lua_pushstring(L, "failed encoding in base64");
    return lua_error(L);
  }

  lua_pushlstring(L, (const char *)out, outsz);

  return 1;
}

int base64dec(lua_State *L) {
  size_t inpsz;
  const char *inp = luaL_checklstring(L, 1, &inpsz);

  size_t outsz = inpsz / 4 * 3;
  unsigned char *out = malloc(outsz + 1); /* NUL terminator */

  int c;

  if ((c = b64_pton(inp, out, outsz)) == -1) {
    lua_pushstring(L, "failed decoding from base64");
    return lua_error(L);
  }

  out[c] = '\0'; /* NUL termination */

  lua_pushlstring(L, (const char *)out, outsz);

  return 1;
}

int query_db(lua_State *L) {
  sqlite3 *db = (sqlite3 *)lua_touserdata(L, lua_upvalueindex(1));
  const char *sql = luaL_checkstring(L, 1);

  int rc = 0;
  sqlite3_stmt *stmt;
  struct bind_param *params = 0;

  rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc) {
    lua_pushfstring(L, "prepare failed: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  int num_params = sqlite3_bind_parameter_count(stmt);

  params = malloc(sizeof(struct bind_param) * num_params);

  if (num_params > 0 && num_params < MAX_PARAMS) {
    for (int i = 0; i < num_params; i++) {
      int si = i + 2;
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
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
      rc = 0;
      break;
    } else if (rc != SQLITE_ROW) {
      lua_pushfstring(L, "Failed executing statement: %s", sqlite3_errstr(rc));
      goto cleanup;
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

int execute_cmd(lua_State *L) {
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

  if ((childpid = fork()) == -1) {
    return luaL_error(L, "Failed forking: %s (code: %d)", strerror(errno),
                      errno);
  }

  if (childpid == 0) {
    close(stdin_pipe[1]);
    close(stdout_pipe[0]);

    if (dup2(stdin_pipe[0], 0) == -1) {
      fprintf(stderr, "Failed duplicating stdin pipe: %s (code: %d)\n",
              strerror(errno), errno);
      exit(1);
    }
    if (dup2(stdout_pipe[1], 1) == -1) {
      fprintf(stderr, "Failed duplicating stdout pipe: %s (code: %d)\n",
              strerror(errno), errno);
      exit(1);
    }

    if (execvp(cmd, argv) == -1) {
      fprintf(stderr, "Failed executing %s: %s (code: %d)\n", cmd,
              strerror(errno), errno);
      exit(1);
    }
  }

  close(stdin_pipe[0]);
  close(stdout_pipe[1]);

  if (inp_size) {
    write(stdin_pipe[1], inp, inp_size);
    close(stdin_pipe[1]);
  }

  int output_size = 0;
  unsigned char *output = read_fd(L, stdout_pipe[0], &output_size);
  if (output == NULL)
    return lua_error(L);

  int status;
  if (waitpid(childpid, &status, 0) == -1)
    return luaL_error(L, "Process failed: %s (code: %d)", strerror(errno),
                      errno);

  if (status)
    return luaL_error(L, "Process exited with status %d", status);

  lua_pushlstring(L, (const char *)output, output_size);
  lua_pushinteger(L, output_size);

  return 2;
}

int http_request(lua_State *L) {
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *headers = 0;

  const char *method = luaL_checkstring(L, 1);
  const char *url = luaL_checkstring(L, 2);

  curl = curl_easy_init();
  if (!curl) {
    lua_pushfstring(L, "Failed creating request: %s (code: %d)",
                    strerror(errno), errno);
    res = CURLE_OBSOLETE;
    goto cleanup;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  if (strcmp(method, "GET") == 0)
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  else if (strcmp(method, "POST") == 0)
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
  else if (strcmp(method, "PUT") == 0)
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);
  else if (strcmp(method, "HEAD") == 0)
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  else
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, (char *)method);

  if (lua_gettop(L) > 2) {
    int top_idx = lua_gettop(L) + 1;

    {
      lua_pushstring(L, "headers");
      int valtype = lua_gettable(L, 3);
      if (valtype != LUA_TNIL) {
        if (valtype != LUA_TTABLE)
          return luaL_error(L, "The 'headers' option must contain a list");

        int num_headers = luaL_len(L, top_idx);
        for (int i = 1; i <= num_headers; i++) {
          lua_pushinteger(L, i);
          lua_gettable(L, top_idx);
          headers = curl_slist_append(headers, lua_tostring(L, -1));
          lua_pop(L, 1);
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      }
      lua_pop(L, 1);
    }

    {
      lua_pushstring(L, "body");
      int valtype = lua_gettable(L, 3);
      if (valtype != LUA_TNIL) {
        if (valtype != LUA_TSTRING)
          return luaL_error(L, "The 'body' option must contain a string");

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, lua_tostring(L, top_idx));
      }
      lua_pop(L, 1);
    }

    {
      lua_pushstring(L, "follow_redirects");
      int valtype = lua_gettable(L, 3);
      if (valtype != LUA_TNIL) {
        if (valtype != LUA_TBOOLEAN)
          return luaL_error(
              L, "The 'follow_redirects' option must contain a boolean");

        if (lua_tointeger(L, -1) == 1)
          curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      }
      lua_pop(L, 1);
    }
  }

  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

  fprintf(stderr, "sending request... ");
  res = curl_easy_perform(curl);
  fprintf(stderr, "done\n");
  if (res != CURLE_OK) {
    lua_pushfstring(L, "Failed sending request: %s", curl_easy_strerror(res));
    goto cleanup;
  }

  lua_newtable(L);

  long status;
  if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK)
    pushtableint(L, "status", (int)status);

  char *content_type;
  if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type) == CURLE_OK)
    pushtablestring(L, "content_type", content_type);

cleanup:
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (res != CURLE_OK)
    return lua_error(L);

  return 1;
}

static int parse_html(lua_State *L, struct resource *res, char *abspath) {
  res->mime = "text/html";

  int top_at_start = lua_gettop(L);

  lua_getglobal(L, "string");
  lua_getfield(L, -1, "gmatch");
  lua_pushstring(L, res->content);
  lua_pushstring(L, "<!%-%- ([^:]+): ([^>]+) %-%->");

  if (lua_pcall(L, 2, 1, 0) != LUA_OK)
    return 1;

  if (!lua_isfunction(L, -1))
    return 1;

  lua_setglobal(L, "iterator");

  while (true) {
    lua_getglobal(L, "iterator");
    lua_pcall(L, 0, 2, 0);

    if (lua_isnil(L, -2))
      break;

    const char *key = lua_tostring(L, -2);
    const char *value = lua_tostring(L, -1);

    if (strcmp(key, "name") == 0) {
      if (res->name != NULL)
        free(res->name);
      res->name = strdup(value);
    } else if (strcmp(key, "template") == 0) {
      res->tmpl = strdup(value);
    } else if (strcmp(key, "status") == 0) {
      if (strcmp(value, "gone") == 0) {
        res->status = MHD_HTTP_GONE;
      } else if (strcmp(value, "moved") == 0) {
        res->status = MHD_HTTP_MOVED_PERMANENTLY;
      } else {
        res->status = MHD_HTTP_OK;
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
      struct tm ctime;
      if (strptime(value, "%Y-%m-%dT%T", &ctime) != NULL)
        res->ctime = mktime(&ctime);
    } else if (strcmp(key, "mtime") == 0) {
      struct tm mtime;
      if (strptime(value, "%Y-%m-%dT%T", &mtime) != NULL)
        res->mtime = mktime(&mtime);
    }

    lua_pop(L, 2);
  }

  lua_pop(L, lua_gettop(L) - top_at_start);

  return 0;
}

static int parse_scss(struct resource *res) {
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
      fprintf(stderr, "Failed parsing SCSS: %s\n", error_message);
    } else {
      fprintf(stderr, "Failed parsing SCSS: no error message available\n");
    }
    rc = 1;
    goto cleanup;
  }

  free(res->content);
  res->content = strdup(sass_context_get_output_string(ctx_out));
  res->size = strlen(res->content);
  res->mime = "text/css";

cleanup:
  sass_delete_data_context(ctx);

  return rc;
}

struct resource *empty_resource(const char *path) {
  struct resource *res = malloc(sizeof(struct resource));
  res->baseurl = NULL;
  res->slug = path;
  res->srcpath = NULL;
  res->mime = NULL;
  res->name = NULL;
  res->status = MHD_HTTP_OK;
  res->content = NULL;
  res->size = 0;
  res->tmpl = NULL;
  res->moved_to = NULL;
  res->ctime = 0;
  res->mtime = 0;
  res->tags = NULL;
  return res;
}

struct resource *error_resource(const char *path, int status) {
  struct resource *res = empty_resource(path);
  res->status = status;
  res->mime = "text/plain";
  const char *prefix = "Error ";
  size_t prefix_len = strlen(prefix);
  size_t status_len = snprintf(NULL, 0, "%d", status);
  size_t total_len = prefix_len + status_len + 1;
  res->content = malloc(total_len);
  snprintf(res->content, total_len, "%s%d", prefix, status);
  res->size = total_len - 1;
  return res;
}

struct resource *load_resource(struct connection_info *con_info,
                               const char *path) {
  fprintf(stderr, "Loading resource %s in host %s\n", path, con_info->host);

  char *fullpath = get_abspath(con_info->host, con_info->is_localhost, path);
  if (fullpath == NULL)
    return NULL;

  enum FileType file_type = OTHER;
  bool found = false;

  struct stat fstat;
  int rc = lstat(fullpath, &fstat);
  if (rc == 0 && S_ISDIR(fstat.st_mode)) {
    fprintf(stderr, "%s is a directory\n", fullpath);

    char *luapath = dup_and_push(fullpath, "/index.lua");
    if (access(luapath, F_OK) == 0) {
      file_type = LUA;
      found = true;
      free(fullpath);
      fullpath = luapath;
    } else {
      free(luapath);
      char *htmlpath = dup_and_push(fullpath, "/index.html");
      if (access(htmlpath, F_OK) == 0) {
        file_type = HTML;
        found = true;
        free(fullpath);
        fullpath = htmlpath;
      } else {
        free(htmlpath);
      }
    }
  } else if (rc == 0 && S_ISLNK(fstat.st_mode)) {
    // this is a symbolic link, return a permanent redirect to the link target
    size_t bufsize = 2048;
    char target[bufsize];
    ssize_t chars = readlink(fullpath, target, bufsize);
    if (chars == -1) {
      fprintf(stderr, "Failed reading link target for %s: %s\n", fullpath,
              strerror(errno));
    } else {
      target[chars] = '\0';
      struct resource *res = empty_resource(path);
      res->moved_to = slugify(con_info->L, target);
      res->status = MHD_HTTP_PERMANENT_REDIRECT;
      return res;
    }
  } else {
    if (access(fullpath, F_OK) == 0) {
      found = true;
    } else if (match(con_info->L, (char *)path, "%.css$")) {
      char *scss_path = replace(con_info->L, fullpath, "%.css$", ".scss");
      if (access(scss_path, F_OK) == 0) {
        file_type = SCSS;
        found = true;
        free(fullpath);
        fullpath = scss_path;
      }
    } else {
      if (access(fullpath, F_OK) != 0) {
        char *luapath = dup_and_push(fullpath, ".lua");
        if (access(luapath, F_OK) == 0) {
          file_type = LUA;
          found = true;
          free(fullpath);
          fullpath = luapath;
        } else {
          char *htmlpath = dup_and_push(fullpath, ".html");
          if (access(htmlpath, F_OK) == 0) {
            file_type = HTML;
            found = true;
            free(fullpath);
            fullpath = htmlpath;
          }
        }
      }
    }
  }

  if (!found) {
    fprintf(stderr, "Did not find a file for resource %s\n", path);
    return NULL;
  }

  fprintf(stderr, "Found resource %s in file %s\n", path, fullpath);

  struct resource *res = empty_resource(path);

  res->srcpath = fullpath;
  res->mime = file_type == LUA    ? "text/x-lua"
              : file_type == SCSS ? "text/css"
              : file_type == HTML ? "text/html"
                                  : magic_file(con_info->magic_db, fullpath);

  if (res->mime == NULL)
    res->mime = "text/plain";

  FILE *fd;
  bool file_opened = false;
  bool file_closed = false;

  rc = lstat(fullpath, &fstat);
  if (rc) {
    fprintf(stderr, "Failed running lstat on %s: %s\n", fullpath,
            strerror(errno));
    res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  res->name = get_basename(fullpath);
  res->size = fstat.st_size;
  res->ctime = fstat.st_ctime;
  res->mtime = fstat.st_mtime;

  fd = fopen(fullpath, "rb");
  if (fd == 0) {
    fprintf(stderr, "Failed opening file %s: %s\n", fullpath, strerror(errno));
    res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  file_opened = true;

  res->content = malloc(res->size + 1);
  if (res->content == 0) {
    fprintf(stderr, "Failed allocating memory for file %s: %s\n", fullpath,
            strerror(errno));
    res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  if (res->size > 0 && fread(res->content, res->size, 1, fd) != 1) {
    fprintf(stderr, "Failed reading file %s: %s\n", fullpath, strerror(errno));
    res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
    goto cleanup;
  }

  res->content[res->size] = '\0';

  fclose(fd);
  file_closed = true;

  if (file_type == LUA) {
    res->mime = "text/x-lua";
  } else if (file_type == HTML) {
    int rc = parse_html(con_info->L, res, fullpath);
    if (rc) {
      fprintf(stderr, "Failed parsing HTML file %s: %d\n", fullpath, rc);
      res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
      goto cleanup;
    }
  } else if (file_type == SCSS) {
    int rc = parse_scss(res);
    if (rc) {
      fprintf(stderr, "Failed parsing SCSS file %s: %d\n", fullpath, rc);
      res->status = MHD_HTTP_INTERNAL_SERVER_ERROR;
      goto cleanup;
    }
  }

cleanup:
  if (file_opened && !file_closed)
    fclose(fd);

  return res;
}

void free_resource(struct resource *res) {
  void *ptrs[] = {res->srcpath,  res->content, res->name,   res->tmpl,
                  res->moved_to, res->tags,    res->baseurl};
  for (int i = 0; i < 7; i++)
    if (ptrs[i] != NULL)
      free(ptrs[i]);
  free(res);
}
