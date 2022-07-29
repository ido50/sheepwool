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
#include <stdbool.h>

#define MAX_PARAMS 100

void dumpstack(lua_State *L);
void pushtableliteral(lua_State *L, const char *key, const char *value);
void pushtablestring(lua_State *L, const char *key, char *value);
void pushtablelstring(lua_State *L, const char *key, char *value, int valsize);
void pushtableint(lua_State *L, const char *key, int value);
bool match(lua_State *L, char *str, const char *pattern);
char *replace(lua_State *L, char *str, const char *pattern, const char *repl);
char *mime_type(lua_State *L, char *path);

int render_tmpl(lua_State *L);
int base64enc(lua_State *L);
int base64dec(lua_State *L);
int query_db(lua_State *L);
int execute_cmd(lua_State *L);
int http_request(lua_State *L);
