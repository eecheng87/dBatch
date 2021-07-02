
#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_module_t  ngx_http_image_filter_module;

ngx_module_t *ngx_modules[] = {
    &ngx_http_image_filter_module,
    NULL
};

char *ngx_module_names[] = {
    "ngx_http_image_filter_module",
    NULL
};

char *ngx_module_order[] = {
    "ngx_http_static_module",
    "ngx_http_gzip_static_module",
    "ngx_http_dav_module",
    "ngx_http_autoindex_module",
    "ngx_http_index_module",
    "ngx_http_random_index_module",
    "ngx_http_access_module",
    "ngx_http_realip_module",
    "ngx_http_write_filter_module",
    "ngx_http_header_filter_module",
    "ngx_http_chunked_filter_module",
    "ngx_http_v2_filter_module",
    "ngx_http_range_header_filter_module",
    "ngx_http_gzip_filter_module",
    "ngx_http_postpone_filter_module",
    "ngx_http_ssi_filter_module",
    "ngx_http_charset_filter_module",
    "ngx_http_xslt_filter_module",
    "ngx_http_image_filter_module",
    "ngx_http_sub_filter_module",
    "ngx_http_addition_filter_module",
    "ngx_http_gunzip_filter_module",
    "ngx_http_userid_filter_module",
    "ngx_http_headers_filter_module",
    "ngx_http_copy_filter_module",
    "ngx_http_range_body_filter_module",
    "ngx_http_not_modified_filter_module",
    "ngx_http_slice_filter_module",
    NULL
};

