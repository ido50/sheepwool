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

#include <dirent.h>
#include <errno.h>
#include <lauxlib.h>
#include <libgen.h>
#include <lua.h>
#include <lualib.h>
#include <sass/base.h>
#include <sass/context.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#if HAVE_INOTIFYTOOLS
#include <inotifytools/inotify.h>
#include <inotifytools/inotifytools.h>
#endif

#include "database.h"
#include "fsbuild.h"
#include "lua_registry.h"

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
        int i = 0;
        char *tag = strtok(value, ", ");
        while (tag) {
          // we are allocating enough memory for one tag (or the number of tags
          // we have) plus one NULL pointer (sentinel)
          if (i > 0)
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

  struct resource *res = malloc(sizeof(struct resource));
  res->owned = true;
  res->baseurl = NULL;
  res->slug = sqlite3_mprintf("/%s", relpath);
  res->srcpath = sqlite3_mprintf("%s", relpath);
  res->mime = mime_type(L, abspath);
  res->name = sqlite3_mprintf("%s", basename(relpath));
  res->status = 0;
  res->content = NULL;
  res->size = 0;
  res->tmpl = NULL;
  res->moved_to = NULL;
  res->ctime = parse_time(fstat.st_mtime);
  res->mtime = parse_time(fstat.st_mtime);
  res->tags = NULL;

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

  res->content = sqlite3_malloc(fstat.st_size + 1);
  if (res->content == 0) {
    rc = errno;
    syslog(LOG_ERR, "Failed allocating memory for file %s: %m", abspath);
    goto cleanup;
  }

  if (fstat.st_size > 0 && fread(res->content, fstat.st_size, 1, fd) != 1) {
    rc = errno;
    syslog(LOG_ERR, "Failed reading file %s: %m", abspath);
    goto cleanup;
  }

  res->content[fstat.st_size] = '\0';

  fclose(fd);
  file_closed = true;

  res->size = fstat.st_size;

  if (strcmp(res->name, "import.sql") == 0) {
    return parse_sql(db, L, res, abspath);
  } else if (match(L, abspath, "%.html$")) {
    rc = parse_html(L, res, abspath);
    if (rc) {
      syslog(LOG_ERR, "Failed parsing HTML file %s: %d", abspath, rc);
      goto cleanup;
    }
  } else if (match(L, abspath, "%.scss$")) {
    rc = parse_scss(L, res, abspath);
    if (rc) {
      syslog(LOG_ERR, "Failed parsing SCSS file %s: %d", abspath, rc);
      goto cleanup;
    }
  } else if (match(L, abspath, "%.lua$")) {
    sqlite3_free(res->mime);
    res->mime = sqlite3_mprintf("text/x-lua");
    res->slug = replace(L, res->slug, "%.lua$", "");
  }

  if (match(L, res->slug, "/index$")) {
    if (!match(L, res->slug, "^/templates/index$")) {
      res->slug = replace(L, res->slug, "/index$", "");
      if (strcmp(res->slug, "") == 0) {
        res->slug = sqlite3_mprintf("/");
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
               sqlite_bind(SQLITE_TEXT, 0, 0, res->slug, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->srcpath, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->mime, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->name, 0),
               sqlite_bind(SQLITE_INTEGER, res->status, 0, NULL, 0),
               sqlite_bind(SQLITE_BLOB, 0, 0, res->content, res->size),
               sqlite_bind(SQLITE_INTEGER, res->size, 0, NULL, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->tmpl, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->moved_to, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->ctime, 0),
               sqlite_bind(SQLITE_TEXT, 0, 0, res->mtime, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed inserting to database: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  rc = execute(db, "DELETE FROM tags WHERE slug=?",
               sqlite_bind(SQLITE_TEXT, 0, 0, res->slug, 0));
  if (rc) {
    syslog(LOG_ERR, "Failed removing existing tags: %s", sqlite3_errstr(rc));
    goto cleanup;
  }

  if (res->tags) {
    for (int i = 0; res->tags[i] != NULL; i++) {
      rc = execute(db, "INSERT INTO tags VALUES (?, ?)",
                   sqlite_bind(SQLITE_TEXT, 0, 0, res->slug, 0),
                   sqlite_bind(SQLITE_TEXT, 0, 0, res->tags[i], 0));
      if (rc) {
        syslog(LOG_ERR, "Failed inserting tag %s: %s", res->tags[i],
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
  free_resource(res);

  return rc;
}

static int build_dir(lua_State *L, sqlite3 *db, char *root, char *relpath) {
  int rc = 0;

  char *abspath = NULL;
  char *absfilepath = NULL;
  char *relfilepath = NULL;
  DIR *dir = NULL;

  if (relpath == NULL) {
    abspath = sqlite3_mprintf("%s", root);
  } else {
    abspath = sqlite3_mprintf("%s/%s", root, relpath);
  }

  char *ignorepath = sqlite3_mprintf("%s/.nowool", abspath);
  if (access(ignorepath, F_OK) == 0) {
    syslog(LOG_DEBUG, "Ignoring directory %s because of .nowool file", abspath);
    goto cleanup;
  }

  syslog(LOG_DEBUG, "Building directory %s", abspath);

  dir = opendir(abspath);
  if (dir == NULL) {
    rc = 1;
    syslog(LOG_ERR, "Failed opening directory %s: %m", abspath);
    goto cleanup;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;

    absfilepath = sqlite3_mprintf("%s/%s", abspath, entry->d_name);
    relfilepath = relpath ? sqlite3_mprintf("%s/%s", relpath, entry->d_name)
                          : sqlite3_mprintf("%s", entry->d_name);

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
  if (dir)
    closedir(dir);
  sqlite3_free(ignorepath);
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
                        "    local resources = sheepwool.query_db(db, [[\n"
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
                        "        [\"baseurl\"] = req.baseurl,\n"
                        "    }\n"
                        "\n"
                        "    return \"application/xml\", sheepwool.render_tmpl(db, "
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

int fswatch(sqlite3 *db, char *root) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  int rc = 0;

#if HAVE_INOTIFYTOOLS
  if (inotifytools_initialize() != 1 ||
      inotifytools_watch_recursively(root, IN_CREATE | IN_MODIFY | IN_MOVE |
                                               IN_DELETE) != 1) {
    syslog(LOG_ERR, "Failed initializing inotify: %s",
           strerror(inotifytools_error()));
    rc = -1;
    goto cleanup;
  }

  syslog(LOG_INFO, "Watching for changes on %s", root);

  struct inotify_event *event = inotifytools_next_event(-1);
  while (event) {
    size_t dirnamelen = 0;
    const char *filename;
    char *dirpath =
        (char *)inotifytools_filename_from_event(event, &filename, &dirnamelen);

    // get the relative directory path (dirpath is the full path to the
    // directory where the file exists)
    char *absfilepath = sqlite3_mprintf("%s%s", dirpath, filename);
    dirpath += strlen(root) + 1;
    char *relfilepath = sqlite3_mprintf("%s%s", dirpath, filename);

    if (strncmp(relfilepath, ".", 1) == 0)
      goto nextevent;

    if (event->mask == IN_DELETE) {
      syslog(LOG_INFO, "Detected DELETE change in %s", relfilepath);
      int rc = execute(db,
                       "DELETE FROM resources "
                       "      WHERE srcpath=?",
                       sqlite_bind(SQLITE_TEXT, 0, 0, relfilepath, 0));
      if (rc) {
        syslog(LOG_ERR, "Failed deleting %s from database: %s", relfilepath,
               sqlite3_errstr(rc));
        goto nextevent;
      }
    } else if (event->mask == IN_CREATE || event->mask == IN_MODIFY) {
      syslog(LOG_INFO, "Detected CREATE/MODIFY change in %s", relfilepath);
      struct stat fstat;
      int rc = lstat(absfilepath, &fstat);
      if (rc) {
        syslog(LOG_ERR, "Failed running lstat on %s: %m", absfilepath);
        goto nextevent;
      }

      rc = import_file(L, db, root, absfilepath, relfilepath, fstat);
      if (rc) {
        syslog(LOG_ERR, "Failed importing file %s: %m", relfilepath);
        goto nextevent;
      }
    } else if (event->mask == (IN_DELETE | IN_ISDIR)) {
      syslog(LOG_INFO, "Detected directory removal in %s", relfilepath);
      char *like = sqlite3_mprintf("%s/%%", relfilepath);
      int rc = execute(db,
                       "DELETE FROM resources "
                       "      WHERE srcpath LIKE ?",
                       sqlite_bind(SQLITE_TEXT, 0, 0, like, 0));
      free(like);
      if (rc) {
        syslog(LOG_ERR, "Failed deleting directory %s from database: %s",
               relfilepath, sqlite3_errstr(rc));
        goto nextevent;
      }
    }

  nextevent:
    free(relfilepath);
    free(absfilepath);
    event = inotifytools_next_event(-1);
  }
#else
  while (true) sleep(1);
#endif

  goto cleanup;

cleanup:
  lua_close(L);

  return rc;
}

int fsbuild(sqlite3 *db, char *root) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);

  syslog(LOG_INFO, "Building database from %s", root);

  int rc = build_dir(L, db, root, NULL);
  if (rc)
    goto cleanup;

  rc = generate_sitemap(db);
  if (rc)
    goto cleanup;

cleanup:
  lua_close(L);

  return rc;
}
