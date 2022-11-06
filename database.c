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
#include <sqlite3.h> // for sqlite3_errstr, sqlite3, sqlite3_stmt, sqlite3_...
#include <stdarg.h>  // for va_list, va_end, va_start, va_arg
#include <stdbool.h> // for bool
#include <stdio.h>   // for fprintf, stderr, NULL
#include <stdlib.h>  // for free, malloc

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
        fprintf(stderr, "Rolling back init transaction\n");
        execute(db, "ROLLBACK");
      }
      return rc;
    }
  }

  return 0;
}

int sqlite_connect(sqlite3 **db, char *dbpath, bool read_only) {
  int rc =
      sqlite3_open_v2(dbpath, db,
                      read_only ? SQLITE_OPEN_READONLY
                                : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      NULL);
  if (rc) {
    fprintf(stderr, "Failed connecting to database %s: %s\n", dbpath,
            sqlite3_errstr(rc));
    goto cleanup;
  }

  sqlite3_busy_timeout(*db, 500);

  rc = sqlite_init(*db, read_only);
  if (rc) {
    fprintf(stderr, "Database initialization failed, exiting\n");
    goto cleanup;
  }

cleanup:
  if (rc)
    sqlite_disconnect(*db);
  return rc;
}

int sqlite_disconnect(sqlite3 *db) { return sqlite3_close(db); }

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
    fprintf(stderr, "Failed preparing statement: %s (code: %d)\n",
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
      fprintf(stderr, "Failed binding parameters: %s\n", sqlite3_errstr(rc));
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
    fprintf(stderr, "Failed executing statement: %s (code: %d)\n",
            sqlite3_errstr(rc), rc);
    goto cleanup;
  }

  rc = 0;

cleanup:
  sqlite3_finalize(stmt);

  return rc;
}
