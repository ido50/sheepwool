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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "server.h"

static void usage(int exit_code) {
  fprintf(exit_code ? stderr : stdout,
          "usage: %s [-h] [-V] [-p PORT] SRC_PATH\n", getprogname());
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

static int sandbox(char *root) {
#if HAVE_PLEDGE
  int rc = pledge("unix sendfd recvfd inet dns proc stdio rpath wpath cpath "
                  "flock fattr unveil",
                  NULL);
  if (rc == -1) {
    fprintf(stderr, "Failed pledging: %s\n", strerror(errno));
    return rc;
  }
#endif

#if HAVE_UNVEIL
  if ((rc = unveil(root, "rwc")) == -1) {
    fprintf(stderr, "Failed unveiling source directory: %s\n", strerror(errno));
    return rc;
  }
  if ((rc = unveil("/usr/local/share/misc/magic.mgc", "r")) == -1) {
    fprintf(stderr, "Failed unveiling magic database: %s\n", strerror(errno));
    return rc;
  }
  if ((rc = unveil("/etc/ssl/cert.pem", "r")) == -1) {
    fprintf(stderr, "Failed unveiling certificates\n");
    return rc;
  }
  if ((rc = unveil(NULL, NULL)) == -1) {
    fprintf(stderr, "Failed closing unveil: %s\n", strerror(errno));
    return rc;
  }
#endif

  return 0;
}

int main(int argc, char **argv) {
  int ch;

  unsigned int port = 8080;
  while ((ch = getopt(argc, argv, "hVp:")) != -1) {
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
    default:
      usage(EXIT_FAILURE);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc != 1) {
    fprintf(stderr, "SRC_PATH must be provided.\n");
    usage(EXIT_FAILURE);
  }

  char *root = argv[0];

  // remove trailing slash from root, if exists
  if (root[strlen(argv[0]) - 1] == '/')
    root[strlen(argv[0]) - 1] = '\0';

  int rc = sandbox(root);
  if (rc)
    exit(EXIT_FAILURE);

  rc = chdir(root);
  if (rc) {
    fprintf(stderr, "Failed changing directory: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  rc = serve(port);
  if (rc)
    fprintf(stderr, "HTTP server failed: %s\n", strerror(errno));

  exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
}
