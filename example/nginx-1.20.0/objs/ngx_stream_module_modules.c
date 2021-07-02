
#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_module_t  ngx_stream_module;
extern ngx_module_t  ngx_stream_core_module;
extern ngx_module_t  ngx_stream_log_module;
extern ngx_module_t  ngx_stream_proxy_module;
extern ngx_module_t  ngx_stream_upstream_module;
extern ngx_module_t  ngx_stream_write_filter_module;
extern ngx_module_t  ngx_stream_limit_conn_module;
extern ngx_module_t  ngx_stream_access_module;
extern ngx_module_t  ngx_stream_geo_module;
extern ngx_module_t  ngx_stream_map_module;
extern ngx_module_t  ngx_stream_split_clients_module;
extern ngx_module_t  ngx_stream_return_module;
extern ngx_module_t  ngx_stream_set_module;
extern ngx_module_t  ngx_stream_upstream_hash_module;
extern ngx_module_t  ngx_stream_upstream_least_conn_module;
extern ngx_module_t  ngx_stream_upstream_random_module;
extern ngx_module_t  ngx_stream_upstream_zone_module;

ngx_module_t *ngx_modules[] = {
    &ngx_stream_module,
    &ngx_stream_core_module,
    &ngx_stream_log_module,
    &ngx_stream_proxy_module,
    &ngx_stream_upstream_module,
    &ngx_stream_write_filter_module,
    &ngx_stream_limit_conn_module,
    &ngx_stream_access_module,
    &ngx_stream_geo_module,
    &ngx_stream_map_module,
    &ngx_stream_split_clients_module,
    &ngx_stream_return_module,
    &ngx_stream_set_module,
    &ngx_stream_upstream_hash_module,
    &ngx_stream_upstream_least_conn_module,
    &ngx_stream_upstream_random_module,
    &ngx_stream_upstream_zone_module,
    NULL
};

char *ngx_module_names[] = {
    "ngx_stream_module",
    "ngx_stream_core_module",
    "ngx_stream_log_module",
    "ngx_stream_proxy_module",
    "ngx_stream_upstream_module",
    "ngx_stream_write_filter_module",
    "ngx_stream_limit_conn_module",
    "ngx_stream_access_module",
    "ngx_stream_geo_module",
    "ngx_stream_map_module",
    "ngx_stream_split_clients_module",
    "ngx_stream_return_module",
    "ngx_stream_set_module",
    "ngx_stream_upstream_hash_module",
    "ngx_stream_upstream_least_conn_module",
    "ngx_stream_upstream_random_module",
    "ngx_stream_upstream_zone_module",
    NULL
};

char *ngx_module_order[] = {
    NULL
};

