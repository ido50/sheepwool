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

#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sqlite3.h>
#include <unistd.h>

#include "database.h"
#include "fsbuild.h"
#include "server.h"

static void usage(int exit_code) {
  fprintf(exit_code ? stderr : stdout,
          "usage: %s [-h] [-V] [-p PORT] [-S] DB_PATH SRC_PATH\n", getprogname());
  exit(exit_code);
}

static unsigned int parse_port_opt(char *optarg) {
  const char *errstr;
  long long port = strtonum(optarg, 1, 50000, &errstr);
  if (errstr != NULL) {
    fprintf(stderr, "port option must be a valid integer\n");
    usage(EXIT_FAILURE);
  }

  if (port < 1 || port > 65535) {
    fprintf(stderr, "port must be between 1 and 65535\n");
    usage(EXIT_FAILURE);
  }

  return (unsigned)port;
}

static int sandbox(char *dbpath, char *root, char *logpath) {
#if HAVE_PLEDGE
  int rc = pledge("unix sendfd recvfd inet dns proc stdio rpath wpath cpath flock fattr unveil", NULL);
  if (rc == -1) {
    fprintf(stderr, "Failed pledging: %s", strerror(errno));
    return rc;
  }
#endif

#if HAVE_UNVEIL
  if ((rc = unveil(dirname(dbpath), "rwc")) == -1) {
    syslog(LOG_ERR, "Failed unveiling database: %m");
    return rc;
  }
  if ((rc = unveil(logpath, "rwc")) == -1) {
    syslog(LOG_ERR, "Failed unveiling log file: %m");
    return rc;
  }
  if ((rc = unveil(root, "r")) == -1) {
    syslog(LOG_ERR, "Failed unveiling source directory: %m");
    return rc;
  }
  if ((rc = unveil("/usr/local/share/misc/magic.mgc", "r")) == -1) {
    syslog(LOG_ERR, "Failed unveiling magic database: %m");
    return rc;
  }
  if ((rc = unveil("/etc/ssl/cert.pem", "r")) == -1) {
    syslog(LOG_ERR, "Failed unveiling certificates");
    return rc;
  }
  if ((rc = unveil(NULL, NULL)) == -1) {
    syslog(LOG_ERR, "Failed closing unveil: %m");
    return rc;
  }
#endif

  return 0;
}

sqlite3 *db;

int main(int argc, char **argv) {
  openlog("sheepwool", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

  int ch;
  bool nobuild = false;
  char *logpath = NULL;

  unsigned int port = 8080;
  while ((ch = getopt(argc, argv, "hVp:l:S")) != -1) {
    switch (ch) {
    case 'h':
      usage(EXIT_SUCCESS);
      break;
    case 'V':
      fprintf(stdout, "%s v%s\n", getprogname(), VERSION);
      exit(EXIT_SUCCESS);
      break;
    case 'p':
      port = parse_port_opt(optarg);
      break;
    case 'l':
      logpath = optarg;
      break;
    case 'S':
      nobuild = true;
      break;
    default:
      usage(EXIT_FAILURE);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc != 2) {
    fprintf(stderr, "DB_PATH and SRC_PATH must be provided.\n");
    usage(EXIT_FAILURE);
  }

  char *root = argv[1];

  /* remove trailing slash from root, if exists */
  if (root[strlen(argv[1])-1] == '/')
    root[strlen(argv[1])-1] = '\0';

  int rc = sandbox(argv[0], root, logpath);
  if (rc)
    exit(EXIT_FAILURE);

  rc = sqlite_connect(&db, argv[0], false);
  if (rc)
    goto cleanup;

  pid_t cpid = -1;

  if (!nobuild) {
    rc = fsbuild(db, root);
    if (rc)
      goto cleanup;

    cpid = fork();
  }

  if (cpid == 0) {
    rc = fswatch(db, root);
  } else {
    if (cpid > 0)
      signal(SIGCHLD, SIG_IGN);

    rc = serve(db, port, logpath);
    if (rc)
      syslog(LOG_ERR, "HTTP server failed: %m");

    if (cpid > 0) {
      if (kill(cpid, SIGQUIT) == -1) {
        syslog(LOG_WARNING, "Failed closing file watcher: %m");
        goto cleanup;
      }

      int wstatus;
      if (waitpid(cpid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
        syslog(LOG_WARNING, "File watched did not respond: %m");
        goto cleanup;
      }
    }
  }

cleanup:
  sqlite_disconnect(db);

  if (rc)
    exit(EXIT_FAILURE);

  exit(EXIT_SUCCESS);
}
