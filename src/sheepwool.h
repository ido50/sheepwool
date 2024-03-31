#include <event2/http.h>
#include <libconfig.h>
#include <magic.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args ...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args ...)    /* Don't do anything in release builds */
#endif

struct redirect {
  const char *from;
  const char *to;
  int status;
};

struct server_info {
	magic_t magic_db;
  char *html_handler;
  char **ignores;
  int num_ignores;
  struct redirect **redirects;
  int num_redirects;
};

enum param_type {
	STRING = 1,
	ARRAY = 2
};

enum resource_type {
  STAT = 1,
  HTML = 2,
  PSGI = 3,
};

struct header_choice {
  const char *value;
  double weight;
};

#define MAX_ENCODINGS 10

struct request {
	enum evhttp_cmd_type method;
  const char *method_str;
  bool is_safe;
  struct evhttp_uri *uri;
  const char *host;
  char *path;
	char *remote_addr;
  ev_uint16_t remote_port;
  struct header_choice supported_encodings[MAX_ENCODINGS];
  int num_supported_encodings;
  const char *delegate;
  int input;
};

struct resource {
	char *fullpath;
  enum resource_type type;
	off_t size;
  struct timespec mtime;
};

struct response {
  int status;
  char etag[11];
  off_t content_length;
  const char *content_type;
  const char *content_encoding;
  struct evbuffer *content;
};

struct response *try_serving_from_cache(
	struct server_info *srv_info,
  struct evhttp_request *conn,
  struct request *req,
  struct resource *res);

char *save_response_to_cache(struct request *req,
                           struct resource *res,
                           struct response *resp,
                           unsigned char *content);

int start_perl(int argc, char **argv, char **env);
void destroy_perl(void);

struct response *serve_psgi(
  struct server_info *srv_info,
  struct evhttp_request *conn,
  struct request *req,
  struct resource *res);

struct response *serve_html(
  struct server_info *srv_info,
  struct evhttp_request *conn,
  struct request *req,
  struct resource *res);

struct response *serve_file(struct server_info *srv_info,
                            struct evhttp_request *conn,
                            struct request *req,
                            struct resource *res);

unsigned char *compress_file(
	struct server_info *srv_info,
	struct request *req,
	struct resource *res,
	struct response *resp);
bool has_suffix(const char *string, const char *suffix);
bool is_compressible(const char *mime);
