#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>

#include <libpq-fe.h>

#include <assert.h>

typedef struct {
  ngx_str_t ConnStr;

  PGconn* Connection;
  ngx_thread_pool_t* ThreadPool;
} ngx_http_whistleblower_main_conf_t;

typedef struct {
  ngx_flag_t Enabled;
} ngx_http_whistleblower_conf_t;

typedef struct {
  u_short ChainId;
  ngx_str_t RemoteAddr;
} ngx_http_whistleblower_ctx_t;

void* ngx_http_whistleblower_create_conf(ngx_conf_t* cf);
char* ngx_http_whistleblower_merge_conf(
    ngx_conf_t* cf, void* parent, void* child);

void* ngx_http_whistleblower_create_main_conf(ngx_conf_t* cf);
char* ngx_http_whistleblower_init_main_conf(ngx_conf_t* cf, void* conf);

ngx_int_t ngx_http_whistleblower_init_process(ngx_cycle_t* cycle);
void ngx_http_whistleblower_exit_process(ngx_cycle_t* cycle);

ngx_int_t ngx_http_whistleblower_init(ngx_conf_t* cf);
u_int32_t extract_field(
    ngx_log_t* logger, ngx_chain_t* in, const char* field_name);

const char THREAD_POOL_NAME[] = "ngx_http_whistleblower_tp_name";

ngx_command_t ngx_http_whistleblower_commands[] = {
  { ngx_string("whistle_blow"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_whistleblower_conf_t, Enabled),
    NULL },
  { ngx_string("whistle_blow_to"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(ngx_http_whistleblower_main_conf_t, ConnStr),
    NULL },

  ngx_null_command
};

ngx_http_module_t ngx_http_whistleblower_module_ctx = {
  NULL,                        /* preconfiguration */
  ngx_http_whistleblower_init, /* postconfiguration */

  ngx_http_whistleblower_create_main_conf, /* create main configuration */
  ngx_http_whistleblower_init_main_conf, /* init main configuration */

  NULL, /* create server configuration */
  NULL, /* merge server configuration */

  ngx_http_whistleblower_create_conf, /* create location configuration */
  ngx_http_whistleblower_merge_conf   /* merge location configuration */
};

ngx_module_t ngx_http_whistleblower_filter_module = {
  NGX_MODULE_V1,
  &ngx_http_whistleblower_module_ctx, /* module context */
  ngx_http_whistleblower_commands, /* module directives */
  NGX_HTTP_MODULE, /* module type */
  NULL, /* init master */
  NULL, /* init module */
  ngx_http_whistleblower_init_process, /* init process */
  NULL, /* init thread */
  NULL, /* exit thread */
  ngx_http_whistleblower_exit_process, /* exit process */
  NULL, /* exit master */
  NGX_MODULE_V1_PADDING
};

ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;

void ngx_http_whistleblower_task_handler(void* data, ngx_log_t* logger) {
  ngx_http_whistleblower_ctx_t* ctx = data;
  ngx_log_error(NGX_LOG_INFO, logger, 0,
      "ngx_http_whistleblower_task_handler: %04Xd %V",
      ctx->ChainId,
      &ctx->RemoteAddr);
  free(ctx->RemoteAddr.data);
  ngx_str_null(&ctx->RemoteAddr);
}

void ngx_http_whistleblower_task_completion(ngx_event_t* ev) {
  // Executed in nginx event loop
}

ngx_int_t ngx_http_whistleblower_filter(
    ngx_http_request_t* r, ngx_chain_t* in) {
  ngx_http_whistleblower_conf_t* conf =
      ngx_http_get_module_loc_conf(r, ngx_http_whistleblower_filter_module);
  if (!conf->Enabled) {
    return ngx_http_next_request_body_filter(r, in);
  }

  u_int32_t chainId = extract_field(r->connection->log, in, "\"blockchain\"");
  if (chainId) {
    ngx_thread_task_t* task = ngx_thread_task_alloc(
        ngx_cycle->pool, sizeof(ngx_http_whistleblower_ctx_t));
    if (task) {
      ngx_http_whistleblower_ctx_t* ctx = task->ctx;
      ctx->ChainId = chainId;
      ctx->RemoteAddr.len = r->connection->addr_text.len;
      // This buffer needs to live longer than ngx_http_request_t,
      // and should be freed at the end of a task.  Easy to manually
      // use malloc/free rather than Nginx's pool.
      ctx->RemoteAddr.data = malloc(ctx->RemoteAddr.len + 1);
      ngx_memcpy(ctx->RemoteAddr.data, r->connection->addr_text.data,
          ctx->RemoteAddr.len);
      ctx->RemoteAddr.data[ctx->RemoteAddr.len] = 0;

      task->handler = ngx_http_whistleblower_task_handler;
      task->event.handler = ngx_http_whistleblower_task_completion;
      task->event.data = ctx;

      ngx_http_whistleblower_main_conf_t* main_conf =
        ngx_http_cycle_get_module_main_conf(
            ngx_cycle, ngx_http_whistleblower_filter_module);
      if (ngx_thread_task_post(main_conf->ThreadPool, task) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_whistleblower_filter: cannot post a task");
      }
    }
    else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
          "ngx_http_whistleblower_filter: cannot create a task");
    }
  }

  return ngx_http_next_request_body_filter(r, in);
}

void* ngx_http_whistleblower_create_conf(ngx_conf_t* cf) {
  ngx_http_whistleblower_conf_t* conf =
      ngx_pcalloc(cf->pool, sizeof(ngx_http_whistleblower_conf_t));
  if (!conf) {
    return NULL;
  }

  conf->Enabled = NGX_CONF_UNSET;
  return conf;
}

char* ngx_http_whistleblower_merge_conf(
    ngx_conf_t* cf, void* parent, void* child) {
  ngx_http_whistleblower_conf_t* prev = parent;
  ngx_http_whistleblower_conf_t* conf = child;
  ngx_conf_merge_value(conf->Enabled, prev->Enabled, 0);
  return NGX_CONF_OK;
}

ngx_int_t ngx_http_whistleblower_init(ngx_conf_t* cf) {
  ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
  ngx_http_top_request_body_filter = ngx_http_whistleblower_filter;
  return NGX_OK;
}

void* ngx_http_whistleblower_create_main_conf(ngx_conf_t* cf) {
  ngx_http_whistleblower_main_conf_t* conf =
      ngx_pcalloc(cf->pool, sizeof(ngx_http_whistleblower_main_conf_t));
  return conf;
}

char* ngx_http_whistleblower_init_main_conf(ngx_conf_t* cf, void* conf_raw) {
  ngx_http_whistleblower_main_conf_t* conf = conf_raw;
  ngx_str_t tp_name = ngx_string(THREAD_POOL_NAME);
  conf->ThreadPool = ngx_thread_pool_add(cf, &tp_name);
  return NGX_CONF_OK;
}

ngx_int_t ngx_http_whistleblower_init_process(ngx_cycle_t* cycle) {
  ngx_http_whistleblower_main_conf_t* conf =
    ngx_http_cycle_get_module_main_conf(
        cycle, ngx_http_whistleblower_filter_module);
  if (!conf) {
    return NGX_OK;
  }

  assert(!conf->Connection);
  if (!conf->ConnStr.data || !conf->ConnStr.len) {
    return NGX_OK;
  }

  PGconn* conn = PQconnectdb((const char*)conf->ConnStr.data);
  if (PQstatus(conn) != CONNECTION_OK) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
        "Connection to database failed: %s", PQerrorMessage(conn));
    PQfinish(conn);
    return NGX_ERROR;
  }

  PGresult* res = PQexec(conn,
      "SELECT pg_catalog.set_config('search_path', '', false)");
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
        "SET failed: %s", PQerrorMessage(conn));
    PQclear(res);
    PQfinish(conn);
    return NGX_ERROR;
  }
  PQclear(res);

  ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
      "Established DB connection: %p", conn);
  conf->Connection = conn;
  return NGX_OK;
}

void ngx_http_whistleblower_exit_process(ngx_cycle_t* cycle) {
  ngx_http_whistleblower_main_conf_t* conf =
    ngx_http_cycle_get_module_main_conf(
      cycle, ngx_http_whistleblower_filter_module);
  PQfinish(conf->Connection);
  conf->Connection = NULL;
  ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Disconnected from DB");
}
