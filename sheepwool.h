#include <lua.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>

#define MAX_TAGS 10
#define MAX_PARAMS 100

struct database {
  sqlite3 *conn;
  const char *err_msg;
  int err_code;
};

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
  char *tags[MAX_TAGS];
};

int sqlite_connect(struct database *, char *, bool);
int sqlite_disconnect(struct database *);
sqlite3_stmt *prepare(struct database *, const char *, ...);
int execute(struct database *, const char *, ...);
int init_rw(struct database *db);
int init_ro(struct database *db);
int fsbuild(struct database *db, char *root);
bool match(lua_State *L, char *str, const char *pattern);
char *replace(lua_State *L, char *str, const char *pattern, const char *repl);
int load_resource(struct database *db, struct resource *res, char *slug);
int render_resource(struct database *db, struct resource *res,
                    struct kreq *req);
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
