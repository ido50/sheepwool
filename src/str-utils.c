// https://github.com/stephenmathieson
// Copyright (c) 2013 Stephen Mathieson
// MIT licensed
#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _XOPEN_SOURCE_EXTENDED
#define _LARGEFILE64_SOURCE
#define _ISOC99_SOURCE
#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define CASE_IS_SEP(c)    ((c) == '-' || (c) == '_' || (c) == ' ')

bool str_starts_with(const char *str, const char *start) {
	for (;; str++, start++)
		if (!*start)
			return true;
		else if (*str != *start)
			return false;
}

bool str_ends_with(const char *str, const char *end) {
	int end_len;
	int str_len;

	if (NULL == str || NULL == end) return false;

	end_len = strlen(end);
	str_len = strlen(str);

	return str_len < end_len
       ? false
       : !strcmp(str + str_len - end_len, end);
}

size_t occurrences(const char *needle, const char *haystack) {
	if (NULL == needle || NULL == haystack) return -1;

	char *pos = (char *)haystack;
	size_t i = 0;
	size_t l = strlen(needle);
	if (l == 0) return 0;

	while ((pos = strstr(pos, needle))) {
		pos += l;
		i++;
	}

	return i;
}

char *str_replace(const char *str, const char *sub, const char *replace) {
	char *pos = (char *) str;
	int count = occurrences(sub, str);

	if (0 >= count) return strdup(str);

	int size = (
		strlen(str)
		- (strlen(sub) * count)
		+ strlen(replace) * count
		) + 1;

	char *result = (char *) malloc(size);
	if (NULL == result) return NULL;
	memset(result, '\0', size);
	char *current;
	while ((current = strstr(pos, sub))) {
		int len = current - pos;
		strncat(result, pos, len);
		strncat(result, replace, strlen(replace));
		pos = current + strlen(sub);
	}

	if (pos != (str + strlen(str))) {
		strncat(result, pos, (str - pos));
	}

	return result;
}

char *case_upper(char *str) {
	for (char *s = str; *s; s++) {
		*s = toupper(*s);
	}
	return str;
}

char *case_lower(char *str) {
	for (char *s = str; *s; s++) {
		*s = tolower(*s);
	}
	return str;
}

char *case_camel(char *str) {
	char *r = str, *w = str;
	// never cap the first char
	while (CASE_IS_SEP(*r)) {
		r++;
	}
	while (*r && !CASE_IS_SEP(*r)) {
		*w++ = *r++;
	}
	while (*r) {
		do {
			r++;
		} while (CASE_IS_SEP(*r));
		*w++ = toupper(*r);
		r++;
		while (*r && !CASE_IS_SEP(*r)) {
			*w++ = *r++;
		}
	}
	*w = 0;
	return str;
}
