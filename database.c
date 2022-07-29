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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "database.h"

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

int bind_params(sqlite3_stmt **stmt, int num_params,
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
  int rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
  if (rc) {
    syslog(LOG_ERR, "Failed preparing statement: %s (code: %d)",
           sqlite3_errstr(rc), rc);
    return rc;
  }

  int num_params = sqlite3_bind_parameter_count(*stmt);

  if (num_params) {
    struct bind_param *params_array =
        malloc(sizeof(struct bind_param) * num_params);

    for (int i = 0; i < num_params; i++) {
      struct bind_param bp = va_arg(*params, struct bind_param);
      params_array[i] = bp;
    }

    va_end(*params);

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
  va_list params;
  va_start(params, sql);

  sqlite3_stmt *stmt;

  int rc = prepare_va(db, &stmt, sql, &params);
  if (rc) {
    goto cleanup;
  }

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
    syslog(LOG_ERR, "Failed executing statement: %s (code: %d)",
           sqlite3_errstr(rc), rc);
    goto cleanup;
  }

  rc = 0;

cleanup:
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

int load_resource(sqlite3 *db, struct resource *res, const char *slug) {
  sqlite3_stmt *stmt;
  int rc = prepare(
      db, &stmt,
      "    SELECT r.slug, r.srcpath, r.name, r.mime, r.status, r.content,"
      "           r.size, r.template, r.moved_to, r.ctime, r.mtime,"
      "           group_concat(t.tag) AS tags"
      "      FROM resources r"
      " LEFT JOIN tags t ON t.slug = r.slug"
      "     WHERE r.slug = ? AND r.status != ?"
      "  GROUP BY r.slug",
      sqlite_bind(SQLITE_TEXT, 0, 0, (char *)slug, 0),
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

  const unsigned char *rslug = sqlite3_column_text(stmt, 0);
  if (strcmp((char *)rslug, "") == 0) {
    rc = SQLITE_NOTFOUND;
    goto cleanup;
  }

  res->slug = sqlite3_mprintf("%s", rslug);
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
  res->owned = true;

cleanup:
  sqlite3_finalize(stmt);

  return rc;
}

void free_resource(struct resource *res) {
  if (!res->owned)
    return;

  sqlite3_free(res->slug);
  sqlite3_free(res->srcpath);
  sqlite3_free(res->name);
  sqlite3_free(res->mime);
  sqlite3_free(res->content);
  sqlite3_free(res->tmpl);
  sqlite3_free(res->moved_to);
  sqlite3_free(res->ctime);
  sqlite3_free(res->mtime);
  sqlite3_free(res->tags);
  sqlite3_free(res->baseurl);
  res->owned = false;
}
