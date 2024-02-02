#include <curl/curl.h>
#include <magic.h>
#include <microhttpd.h>
#include <regex.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>
#include <utarray.h>
#include <uthash.h>

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args ...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args ...)    /* Don't do anything in release builds */
#endif

struct server_info {
	magic_t magic_db;
  CURL *curl;
  const char *default_title;
  const char **ignore;
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

struct resource {
	char *fullpath;
  enum resource_type type;
	off_t size;
  struct timespec mtime;
};

struct param {
  char *name;
  const char *value;
  UT_hash_handle hh;
};

struct body_param {
  const char *name;
	enum param_type type;
	const char *string_value;
	UT_array *array_value;
  UT_hash_handle hh;
};

struct header_choice {
  const char *value;
  double weight;
};

#define MAX_ENCODINGS 10

struct response {
  int status;
  off_t size;
  const char *content_encoding;
  unsigned char *content_type;
  unsigned char *etag;
  unsigned char *location;
  unsigned char *content;
  struct MHD_Response *backend;
};

struct request {
  bool is_safe;
	struct MHD_PostProcessor *postprocessor;
  const char *host;
  const char *scheme;
	const char *version;
	const char *method;
	const char *raw_path;
  CURLU *url;
  char *dec_path;
	struct param *headers;
	struct body_param *body_params;
	char *remote;
	struct resource *res;
  struct header_choice supported_encodings[MAX_ENCODINGS];
  int num_supported_encodings;
  struct response *resp;
};

enum MHD_Result try_serving_from_cache(
	struct server_info *srv_info,
	struct MHD_Connection *conn,
	struct request *req);
int save_response_to_cache(struct server_info *srv_info, struct request *req);

int start_perl(int argc, char **argv, char **env);
enum MHD_Result serve_psgi(struct MHD_Connection *conn, struct request *req);
void destroy_perl(void);

enum MHD_Result serve_html(struct server_info *srv_info, struct MHD_Connection *conn, struct request *req);

bool compress_file(struct server_info *srv_info, struct request *req);

bool has_suffix(const char *string, const char *suffix);
bool is_compressible(const char *mime);
void parse_accept_encoding(struct request *req);
enum MHD_Result serve_file(struct server_info *srv_info,
                                  struct MHD_Connection *conn,
                                  struct request *req);
