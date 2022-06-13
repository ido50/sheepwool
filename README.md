# SheepWool

**Semi-Static Site Generator and Server.**

<!-- vim-markdown-toc GFM -->

- [Synopsis](#synopsis)
- [Features](#features)
- [Documentation](#documentation)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Site Structure](#site-structure)
  - [Site Generation](#site-generation)
  - [Site Deployment](#site-deployment)
- [Status](#status)
  - [Roadmap](#roadmap)
- [History](#history)
- [License](#license)

<!-- vim-markdown-toc -->

## Synopsis

**SheepWool** is a C application for the generation and serving of dynamic websites.
It takes a directory tree of static files, templated HTML files, and Lua scripts;
parses them into a SQLite database, and serves the database over FastCGI.

This allows website creators to work exactly as with static-site generators
during development, but still have a fully dynamic website. The SQLite database
can also be used for whatever purpose needed, thus making SheepWool useable
as a simple web application framework.

SheepWool currently targets OpenBSD and Linux.

## Features

- Entire website content stored in a SQLite database.
- Templated HTML resources via [etlua](https://github.com/leafo/etlua) (no Markdown support, just pure HTML).
- Dynamic resources via [Lua](https://lua.org/) 5.3.
- Automatic compilation of scss files to css.
- Ability to create redirects and other responses such as 410 Gone.
- Ability to execute SQL commands from SQL files during website build.
- Automatic sitemap generation.
- Sandboxed under OpenBSD using [`pledge(2)`](https://man.openbsd.org/pledge) and [`unveil(2)`](https://man.openbsd.org/unveil) for security.

## Documentation

### Dependencies

- [SQLite](https://sqlite.org/) 3.35.5+
- [kcgi](https://kristaps.bsd.lv/kcgi/) 0.13.0+
- [Lua](https://lua.org/) 5.3
- [libsass](https://sass-lang.com/libsass)
- libmagic
- [libcurl](https://curl.se/libcurl/)

### Installation

```
% ./configure
% make
# make install
```

Note that `make install` currently installs the `sheepwool` binary into the
/var/www/cgi-bin directory. Example commands in the following sections take into
account that this directory is in your `$PATH`.

### Site Structure

When generating the website's database, SheepWool recursively traverses the
source tree and utilizes the following flow:

- If the root directory contains a file called META, it will be used to create
  resources with special status codes. The file should contain lines in the
  following format:

  ```
  /path/to/resource status [/path/to/new/resource]
  ```

  Where `status` is `not_found`, `gone` or `permanent`. The first two will cause
  requests to /path/to/resource to return 404 and 410 statuses, respectively.
  If the status is `permanent`, a new path for an existing resource should be
  provided as well, and requests to the old path will result in a 301 redirect
  to the new path.

- If a directory contains a file called .nowool, the directory is completely
  skipped (including all its subdirectories).

- If a file is called import.sql (in any directory), it is treated as input for
  SQLite and simply executed on the database. This is useful for creating new
  tables, inserting custom data, _et cetra_. It should be noted that every
  generation of the file re-runs it, so it should handle conflicts gracefully.

- If a file has an .html extension, SheepWool will strip its .html extension
  for purposes of the file's path in the website (called "slug" internally),
  and read it to look for metadata in HTML comments. Here is an example of an
  HTML file called hello-world.html in the root directory of the website, and
  that includes all supported meta attributes:

  ```html
  <!-- name: Hello World -->
  <!-- tags: one, two -->
  <!-- status: pub -->
  <!-- template: /templates/post -->
  <!-- ctime: 2022-01-02T16:28:52 -->
  <!-- mtime: 2022-01-03T12:40:32 -->

  <p>Hello World</p>
  ```

  This will generate a resource called /hello-world in the website database,
  whose name/title is "Hello World", tagged with the "one" and "two" tags,
  whose status is "pub" (for "published", the default), using the template file
  /templates/post.html, and with the provided creation and last modification
  dates from the ctime and mtime attributes, respectively.

  Other supported statuses are "unpub" (for unpublished), "gone" and "moved".

  When serving this file, SheepWool will render the template file /templates/post
  with the variable "content" containing the content of hello-world.html, and
  more variables described below. Templates themselves can define their own
  templates, thus creating a chain of templates (there is no limit on the number
  of templates in the chain). Each time a template is rendered, the entire
  output is used as the "content" variable for the next template in the chain.

  The following variables are available in templates:

  - `status`: the HTTP status code to be returned (usually 200). An integer.
  - `baseurl`: the base URL of the request (e.g. "https://my-domain.com"). A
    string. Never contains a trailing slash.
  - `reqpath`: the request's path (e.g. "/hello-world"). A string.
  - `slug`: the matched resource's slug, usually the same as `reqpath`.
  - `srcpath`: the path in the source directory from which the resource was built.
  - `name`: the name of the resource (from the "name" meta attribute, if exists,
    otherwise the name of the file, i.e. "hello-world.html").
  - `content`: the content of the resource.
  - `ctime`: the resource's creation time, a string in the format "%Y-%m-%dT%H:%M:%S".
  - `mtime`: the resource's modification time, same format as `ctime`.
  - `tags`: a list of zero or more tags.

  See the [etlua documentation](https://github.com/leafo/etlua) for more information on how to write templates.

- If a file has a .lua extension, it is assumed to be a dynamic resource.
  SheepWool will strip is .lua extension, and insert it into the database as-is.
  The file can have any format, but MUST return a table with a key called
  "render", which contains a function of the following format:

  ```lua
  function render(sheepwool, db, req)
  ```

  In this function, `sheepwool` is a library-table containing utility functions
  useable by the function; `db` is a pointer to the SQLite database connection;
  `req` is a table containing metadata about the request.

  The `render` function should return two values: the MIME type of the resource,
  and the contents. This means Lua resources can be used to generate any type
  of content, not just HTML.

  The following functions are included in the `sheepwool` library:

  - `query`: executes a SQL query against the database. Always returns an array,
    even if only one row is returned. Accepts the following parameters: `db`
    (the database connection pointer), `sql` (the SQL query to execute), and
    zero or more binding parameters of any type.

  - `execute`: executes a command in a shell with optional standard input and
    returns its output. Accepts the following parameters: `cmd` (the name or path
    of the command to execute); `args` (an array of arguments to the command);
    and optionally `stdin` (data to pipe into the command's standard input).
    Returns two values: the command's standard output, and the size of the
    output.

  - `render`: renders an HTML template from the database and returns the output.
    Accepts the following parameters: `db` (the database connection pointer),
    `tmpl_name` (the name of the template to render, e.g. "/templates/post"),
    and `context` (a table of metadata to make available as variables inside the
    template).

  - `post`: makes an HTTP POST request to a URL and returns the response body.
    Accepts the following parameters: `url` (the URL of the request), `headers`
    (a table of request headers) and `body` (the body of the request).

  - `base64_encode`: encodes a binary value in base 64 encoding. Accepts the
    value to encode, and returns the encoded value.

  The following data is included in the `req` table:

  - `scheme`: the request scheme, e.g. "https" or "http".
  - `host`: the request host, e.g. "my-domain.com".
  - `method`: the request method, e.g. "GET".
  - `root`: the root path (i.e. SCRIPT_NAME), usually empty.
  - `path`: the request path, e.g. "/hello-world".
  - `remote`: the client address.
  - `status`: the (currently estimated) response status, integer.
  - `params`: a table of request parameters from query string or body.
    File uploads are also supported. The table will include a table for each
    uploaded file, with the keys `content`, which includes the contents of the
    file in base64 encoding; `mime`, the MIME type of the file; and `size`, the
    size of the file (before base64 encoding).
  - `headers`: a table of request headers.

  Here's an example of a Lua resource that loads data from the database,
  renders it into an HTML template, and returns the output.

  ```lua
  function render(sheepwool, db, req)
      -- Load five latest posts from the blog
      local latest_posts = sheepwool.query(db, [[
          SELECT r.slug, r.name, r.ctime, r.mtime, group_concat(t.tag) AS tags
          FROM resources r
          LEFT JOIN tags t ON t.slug = r.slug
          WHERE r.slug LIKE '/blog/%' AND r.status = 0
          GROUP BY r.slug
          ORDER BY r.ctime DESC
          LIMIT 5
      ]])

      -- Render into a template
      return "text/html", sheepwool.render(db, "/templates/index", {
          ["name"] = "Some Guy's Personal Blog",
          ["posts"] = latest_posts,
      })
  end

  return {
      ["render"] = render,
  }
  ```

- If a file has a .scss extension, it is compiled using libsass and stored as a
  css file. For example, a file called /styles/main.scss will generate a resource
  called /styles/main.css.

- If a file in the root directory is called error.html or error.lua, it will be
  used for rendering error responses. This happens whenever a resource cannot be
  served for any reason: the requested resource does not exist, or the rendering
  failed. The same rules as for HTML and Lua files apply. You will probably
  want to look at the response status in this file to generate different error
  responses based on the situation.

- Otherwise, the file is treated as a static file. SheepWool will attempt to
  find out its MIME type using libmagic, and store it in the database as-is.

- When all files have been processed, SheepWool generates a sitemap resource
  under the /sitemap.xml path.

### Site Generation

To build or synchronize the website's database file from a source directory,
simply execute:

```sh
sheepwool build /path/to/database /path/to/source
```

Note that the `build` command will override existing data in the "resources",
"tags" and "vars" tables, but leave any other tables as-is, so the command
should be safe to run on production databases.

### Site Deployment

On OpenBSD, it is recommended to use [`kfcgi`](https://kristaps.bsd.lv/kcgi/kfcgi.8.html) to deploy a SheepWool website.
The `kfcgi` binary is part of the kcgi dependency.

To serve a website previously built via SheepWool, execute:

```sh
kfcgi -- sheepwool serve /path/to/database
```

You will probably wish to do this in an rc script.

I haven't been able to successfuly use `kfcgi` on Linux, and instead use
[`spawn-fcgi`](https://github.com/lighttpd/spawn-fcgi), like so:

```sh
spawn-fcgi -- sheepwool serve /path/to/database
```

## Status

I am currently using SheepWool to build and serve several websites, including
my [personal website](https://ido50.net/), but I cannot guarantee that it is properly secure and
free of critical bugs. While I have many years of development experience with
many programming languages, this is my first serious C project, so I wouldn't
be surprised if there are memory/security-related issues.

### Roadmap

See [list of enhancements](https://github.com/ido50/sheepwool/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement) in the issues page.

## History

I've been using the name SheepWool for my content management systems for over
twenty years now. Originally, it was a Perl/CGI application, then a Perl/FastCGI
application, then a Perl/PSGI application, then a Go application, then a
Python/ASGI application, and finally a C/FastCGI application. I have written and
re-written it all these times to fit my needs. There really isn't any resemblance
between this iteration of SheepWool and earlier ones, but it made sense to me
to continue using this name. Since there were at least four earlier iterations,
this one is starting at version 5.0.0, though this is entirely arbitrary.

## License

All sources use the ISC (like OpenBSD) license. See the [LICENSE.md](LICENSE.md) file for details.
