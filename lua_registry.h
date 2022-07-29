#include <lua.h>
#include <stdbool.h>

#define MAX_PARAMS 100

void dumpstack(lua_State *L);
void pushtablestring(lua_State *L, const char *key, char *value);
void pushtablelstring(lua_State *L, char *key, int keysize, char *value,
                      int valsize);
void pushtableint(lua_State *L, const char *key, int value);
bool match(lua_State *L, char *str, const char *pattern);
char *replace(lua_State *L, char *str, const char *pattern, const char *repl);
char *mime_type(lua_State *L, char *path);
int lua_render(lua_State *L);
int lua_base64_encode(lua_State *L);
int lua_base64_decode(lua_State *L);
int lua_query(lua_State *L);
int lua_execute(lua_State *L);
int lua_post_request(lua_State *L);
