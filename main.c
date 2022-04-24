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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sheepwool.h"

static void usage(int exit_code) {
  FILE *output = exit_code ? stderr : stdout;
  const char *progname = getprogname();
  fprintf(output, "usage: %s build db_path src_path\n", progname);
  fprintf(output, "       %s serve db_path\n", progname);
  exit(exit_code);
}

int main(int argc, char **argv) {
  if (argc < 3 || (argc == 3 && strcmp(argv[1], "build") == 0)) {
    usage(EXIT_FAILURE);
  }

  int ret = 0;
  if (strcmp(argv[1], "build") == 0)
    ret = fsbuild(argv[2], argv[3]);
  else if (strcmp(argv[1], "serve") == 0)
    ret = serve(argv[2]);
  else
    usage(EXIT_FAILURE);

  return ret;
}
