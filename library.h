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
#include <lua.h>
#include <magic.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <time.h>

#define MAX_PARAMS 100

enum ContentType {
  CT_OTHER = 0,
  CT_URLENCODED = 1,
  CT_MULTIPART = 2,
  CT_JSON = 3
};

struct connection_info {
  magic_t magic_db;
  sqlite3 *db;
  enum ContentType content_type;
  lua_State *L;
  bool is_localhost;
  const char *scheme;
  const char *host;
  const char *remote;
  const char *referer;
  const char *agent;
  const char *method;
  const char *path;
  bool parse_body;
  struct MHD_PostProcessor *postprocessor;
  struct resource *resource;
  unsigned int status;
};

struct resource {
  char *baseurl;
  const char *slug;
  char *srcpath;
  const char *mime;
  char *name;
  int status;
  char *content;
  int size;
  char *tmpl;
  char *moved_to;
  time_t ctime;
  time_t mtime;
  char **tags;
};

void dumpstack(lua_State *L);
void pushtableliteral(lua_State *L, const char *key, const char *value);
void pushtablestring(lua_State *L, const char *key, char *value);
void pushtablelstring(lua_State *L, const char *key, char *value, int valsize);
void pushtableint(lua_State *L, const char *key, int value);
void pushtableclosure(lua_State *L, const char *name, lua_CFunction fn, int n,
                      ...);
bool match(lua_State *L, char *str, const char *pattern);
char *replace(lua_State *L, char *str, const char *pattern, const char *repl);
bool str_starts_with(const char *str, const char *start);
char *get_abspath(const char *host, bool is_localhost, const char *path);
char *parse_time(time_t time);
struct resource *empty_resource(const char *path);
struct resource *error_resource(const char *path, int status);
struct resource *load_resource(struct connection_info *con_info,
                               const char *path);
void free_resource(struct resource *load_resource);
int list_resources(lua_State *L);
int render_tmpl(lua_State *L);
int base64enc(lua_State *L);
int base64dec(lua_State *L);
int query_db(lua_State *L);
int execute_cmd(lua_State *L);
int http_request(lua_State *L);
