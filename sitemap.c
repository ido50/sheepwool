static int generate_sitemap(sqlite3 *db) {
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
    fprintf(stderr, "Failed inserting sitemap template: %s",
            sqlite3_errstr(rc));
    goto cleanup;
  }

  const char *content =
      "function render(sheepwool, db, req)\n"
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
    fprintf(stderr, "Failed inserting sitemap to database: %s",
            sqlite3_errstr(rc));
    goto cleanup;
  }

cleanup:
  return rc;
}
