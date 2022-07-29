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
#include <sqlite3.h>
#include <stdbool.h>

enum status { PUB, UNPUB, MOVED, GONE };

struct resource {
  bool owned;
  char *baseurl;
  char *slug;
  char *srcpath;
  char *mime;
  char *name;
  enum status status;
  char *content;
  int size;
  char *tmpl;
  char *moved_to;
  char *ctime;
  char *mtime;
  char **tags;
};

int sqlite_connect(sqlite3 **, char *, bool);
int sqlite_disconnect(sqlite3 *);
int prepare(sqlite3 *, sqlite3_stmt **, const char *, ...);
int execute(sqlite3 *, const char *, ...);
int load_resource(sqlite3 *db, struct resource *res, const char *slug);
void free_resource(struct resource *res);

struct bind_param {
  int type;
  int int_value;
  double double_value;
  char *char_value;
  unsigned long size;
};

struct bind_param sqlite_bind(int type, int int_value, double double_value,
                              char *char_value, unsigned long size);
int bind_params(sqlite3_stmt **stmt, int num_params, struct bind_param *params);
