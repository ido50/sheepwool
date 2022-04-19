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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <kcgi.h>

#include "sheepwool.h"

static void http_open(struct kreq *r, enum khttp code, char *mime) {
  khttp_head(r, kresps[KRESP_STATUS], "%s", khttps[code]);
  khttp_head(r, kresps[KRESP_CONTENT_TYPE], "%s", mime);
  khttp_head(r, "X-Content-Type-Options", "nosniff");
  khttp_head(r, "X-Frame-Options", "DENY");
  khttp_head(r, "X-XSS-Protection", "1; mode=block");
}

static int serve(struct database *db) {
  struct kreq req;
  struct kfcgi *fcgi;

  if (khttp_fcgi_init(&fcgi, NULL, 0, NULL, 0, 0) != KCGI_OK)
    return EXIT_FAILURE;

  while (khttp_fcgi_parse(fcgi, &req) == KCGI_OK) {
    if (req.method != KMETHOD_GET && req.method != KMETHOD_HEAD) {
      http_open(&req, KHTTP_405, (char *)"text/plain");
      khttp_free(&req);
      continue;
    }

    struct resource res;

    int rc = load_resource(db, &res, req.fullpath);
    if (rc == SQLITE_NOTFOUND) {
      http_open(&req, KHTTP_404, (char *)"text/plain");
      khttp_body(&req);
      khttp_free(&req);
      continue;
    } else if (rc != SQLITE_OK) {
      fprintf(stderr, "Failed loading resource %s: %s\n", req.fullpath,
              db->err_msg);
      http_open(&req, KHTTP_500, (char *)"text/plain");
      khttp_body(&req);
      khttp_free(&req);
      continue;
    }

    enum khttp status;

    if (res.status == MOVED) {
      status = KHTTP_301;
      res.mime = sqlite3_mprintf("text/plain");
      res.content = sqlite3_mprintf("Moved to %s", res.moved_to);
      res.size = strlen(res.content);
    } else if (res.status == GONE) {
      status = KHTTP_410;
      res.mime = sqlite3_mprintf("text/plain");
      res.content = sqlite3_mprintf("No longer exists");
      res.size = strlen(res.content);
    } else {
      status = KHTTP_200;
      const char *scheme = req.scheme == KSCHEME_HTTPS ? "https" : "http";
      res.baseurl = sqlite3_mprintf("%s://%s", scheme, req.host);

      rc = render_resource(db, &res, &req);
      if (rc) {
        fprintf(stderr, "Failed rendering resource %s\n", req.fullpath);
        http_open(&req, KHTTP_500, (char *)"text/plain");
        khttp_body(&req);
        khttp_free(&req);
        free_resource(&res);
        continue;
      }
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

  khttp_fcgi_free(fcgi);
  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
#if HAVE_PLEDGE
  if (pledge("stdio", NULL) == -1) {
    kutil_err(NULL, NULL, "pledge");
    return EXIT_FAILURE;
  }
#endif

#ifdef __linux__
  const char *datadir = "/var/www/data";
#else
  const char *datadir = DATADIR;
#endif

  char *dbpath = sqlite3_mprintf("%s/%s.wool", datadir, argv[1]);
  printf("dbpath: %s\n", dbpath);

  struct database db;
  if (connect(&db, dbpath, false)) {
    kutil_err(NULL, NULL, "Failed connecting to DB (%d): %s", db.err_code,
              db.err_msg);
    return EXIT_FAILURE;
  }

  int ret = fsbuild(&db, argv[2]);
  if (ret == 0) {
    printf("Starting FCGI server\n\n");
    ret = serve(&db);
  }

  disconnect(&db);
  sqlite3_free(dbpath);
  return ret;
}
