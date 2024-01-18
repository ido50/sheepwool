// https://github.com/stephenmathieson
// Copyright (c) 2013 Stephen Mathieson
// MIT licensed
#include <stdbool.h>
#include <stdio.h>

bool str_starts_with(const char *str, const char *start);
bool str_ends_with(const char *str, const char *end);
size_t occurrences(const char *needle, const char *haystack);
char *str_replace(const char *str, const char *sub, const char *replace);
char *case_upper(char *);
char *case_lower(char *);
char *case_camel(char *);
