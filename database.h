#include <sqlite3.h>
#include <stdbool.h>

enum status { PUB, UNPUB, MOVED, GONE };

struct resource {
  char *baseurl;
  char *slug;
  char *srcpath;
  char *mime;
  char *name;
  enum status status;
  char *content;
  int size;
  char *tmpl;
  char *moved_to;
  char *ctime;
  char *mtime;
  char **tags;
};

int sqlite_connect(sqlite3 **, char *, bool);
int sqlite_disconnect(sqlite3 *);
int prepare(sqlite3 *, sqlite3_stmt **, const char *, ...);
int execute(sqlite3 *, const char *, ...);
int load_resource(sqlite3 *db, struct resource *res, char *slug);
void free_resource(struct resource *res);

struct bind_param {
  int type;
  int int_value;
  double double_value;
  char *char_value;
  unsigned long size;
};

struct bind_param sqlite_bind(int type, int int_value, double double_value,
                              char *char_value, unsigned long size);
int bind_params(sqlite3_stmt **stmt, int num_params, struct bind_param *params);
