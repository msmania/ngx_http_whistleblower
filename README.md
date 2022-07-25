# Nginx Whistleblower module

This module issues an INSERT transaction for a connected PostgreSQL instance
if a specific pattern is found in the request body.

## Build

You need to download the source of [OpenSSL](https://www.openssl.org/)
and [PCRE](https://pcre.org/).

You also need [libpq](https://www.postgresql.org/docs/current/libpq.html).  You
can build PostgreSQL from source, but installing the *libpq-dev* suffices as
below.

```
sudo apt install libpq-dev
```

Here's a minimum configuration example to build Nginx with this module,
assuming all the sources are placed in /data/src.

```
$ auto/configure \
 --with-cc-opt='-g -O0 -I/usr/include/postgresql' \
 --with-ld-opt='-lpq' \
 --prefix=/data/bin/nginx/dev \
 --conf-path=conf/nginx.conf \
 --error-log-path=logs/error.log \
 --http-log-path=logs/access.log \
 --with-debug \
 --with-threads \
 --with-pcre=/data/src/pcre2 \
 --with-openssl=/data/src/openssl \
 --add-module=/data/src/ngx_http_whistleblower
```

## Nginx Configuration

Here's the configuration example to load this module.  The *threads* parameter
for the thread pool *ngx_http_whistleblower_tp_name* must be 1.

```
worker_processes 1;
thread_pool ngx_http_whistleblower_tp_name threads=1 max_queue=65536;

events {
}

error_log /data/bin/nginx/dev/logs/debug.log info;

http {
  whistle_blow_to "<PostgreSQL connection string>";
  server {
    listen 0.0.0.0:8888;
    listen [::]:8888;
    location / {
      proxy_pass http://127.0.0.1:9000;
      whistle_blow on;
    }
  }
}
```
