// Copyright (c) 2021 Cesanta Software Limited
// All rights reserved
//
// Example HTTP client. Connect to `s_url`, send request, wait for a response,
// print the response and exit.
// You can change `s_url` from the command line by executing: ./example YOUR_URL
//
// To enable SSL/TLS for this client, build it like this:
//    make MBEDTLS=/path/to/your/mbedtls/installation
//    make OPENSSL=/path/to/your/openssl/installation

#include "mongoose.h"
#include <pthread.h>

#define n 1
pthread_t t[n];
pthread_mutex_t lock;

// The very first web page in history. You can replace it from command line
static const char *s_url = "http://info.cern.ch";

long get_elapse(struct timespec start, struct timespec end) {
    return ((long)1.0e+9 * end.tv_sec + end.tv_nsec) -
           ((long)1.0e+9 * start.tv_sec + start.tv_nsec);
}

// Print HTTP response and signal that we're done
static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_CONNECT) {
    // Connected to server. Extract host name from URL
    struct mg_str host = mg_url_host(s_url);

    // If s_url is https://, tell client connection to use TLS
    if (mg_url_is_ssl(s_url)) {
      struct mg_tls_opts opts = {.ca = "ca.pem", .srvname = host};
      mg_tls_init(c, &opts);
    }
    // Send request
    mg_printf(c,
              "GET %s HTTP/1.0\r\n"
              "Host: %.*s\r\n"
              "\r\n",
              mg_url_uri(s_url), (int) host.len, host.ptr);
  } else if (ev == MG_EV_HTTP_MSG) {
    // Response is received. Print it
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    printf("%.*s", (int) hm->message.len, hm->message.ptr);
    c->is_closing = 1;         // Tell mongoose to close this connection
    *(bool *) fn_data = true;  // Tell event loop to stop
  } else if (ev == MG_EV_ERROR) {
    *(bool *) fn_data = true;  // Error, tell event loop to stop
  }
}

void *worker(void *arg) {
    int k;
    for(k = 0; k < 1; k++){
    struct timespec t1, t2;
    struct mg_mgr mgr;                        // Event manager
    bool done = false;                        // Event handler flips it to true
    mg_mgr_init(&mgr);                        // Initialise event manager
    mg_http_connect(&mgr, s_url, fn, &done);  // Create client connection
    clock_gettime(CLOCK_MONOTONIC, &t1);
    while (!done) mg_mgr_poll(&mgr, 1000);    // Infinite event loop
    clock_gettime(CLOCK_MONOTONIC, &t2);
    pthread_mutex_lock(&lock);
    printf("\n->> %ld\n", get_elapse(t1, t2));
    pthread_mutex_unlock(&lock);
    mg_mgr_free(&mgr);                        // Free resources
    usleep(100000);
    }
}

int main(int argc, char *argv[]) {
  int i;
  if (argc > 1) s_url = argv[1];            // Use URL from command line
  pthread_mutex_init(&lock, NULL);
  for (i = 0; i < n; i++)
    pthread_create(&t[i], NULL, worker, NULL);
  for (i = 0; i < n; i++)
    pthread_join(t[i], NULL);
  pthread_mutex_destroy(&lock);

  return 0;
}