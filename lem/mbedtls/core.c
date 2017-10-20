/*
 Copyright (c) 2017 Ralph Augé, All rights reserved.
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
*/
#include <lem.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

#include "mbedtls/config.h"

#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t 
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

const char *g_mbedtls_drbg_mt = "mtls_drbg_mt";
const char *g_mbedtls_conf_mt = "mtls_conf_mt";
const char *g_mbedtls_ssl_context_mt = "mtls_ssl_context_mt";


char *heap_err_msg(const char *fmt, ...) {
  char errmsg[1024];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(errmsg, sizeof errmsg, fmt, ap);
  va_end(ap);

  return strdup(errmsg);
}

static void lem_mbedtls_debug_callback(
    void *ctx, int level,
    const char *file, int line,
    const char *str) {

  ((void) level);

  mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *) ctx);
}

struct lem_mbedtls_drbg {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
};

int lem_mbedtls_drbg_gc(lua_State *L) {
  struct lem_mbedtls_drbg *drbg = (struct lem_mbedtls_drbg*)lua_touserdata(L, 1);

  mbedtls_ctr_drbg_free(&drbg->ctr_drbg);
  mbedtls_entropy_free(&drbg->entropy);

  return 0;
}

int lem_mbedtls_new_drbg(lua_State *T) {
  int ret;
  const char *pers = "ssl_server";
  struct lem_mbedtls_drbg *drbg = (struct lem_mbedtls_drbg*) lua_newuserdata(T, sizeof(*drbg));


  mbedtls_entropy_init(&drbg->entropy);
  mbedtls_ctr_drbg_init(&drbg->ctr_drbg);

  /* Seeding the random number generator... */

  if ((ret = mbedtls_ctr_drbg_seed(
          &drbg->ctr_drbg, mbedtls_entropy_func, &drbg->entropy,
          (const unsigned char *) pers,
          strlen(pers))) != 0) {
    char *err;
    err = heap_err_msg("failed - mbedtls_ctr_drbg_seed returned -0x%04x", -ret);
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, err);
    free(err);
    return 2;
  }

  luaL_getmetatable(T, g_mbedtls_drbg_mt);
  lua_setmetatable(T, -2);

  return 1;
}

struct lem_mbedtls_conf {
  mbedtls_ssl_config conf;
  mbedtls_ssl_cache_context cache;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
  int client_or_server_mode;
};

int lem_mbedtls_conf_gc(lua_State *L) {
  struct lem_mbedtls_conf *conf = (struct lem_mbedtls_conf*)lua_touserdata(L, 1);

  if (conf->client_or_server_mode == MBEDTLS_SSL_IS_SERVER) {
    mbedtls_ssl_cache_free(&conf->cache);
  }

  mbedtls_ssl_config_free(&conf->conf);
  mbedtls_x509_crt_free(&conf->srvcert);
  mbedtls_pk_free(&conf->pkey);

  return 0;
}


int lem_mbedtls_new_conf(lua_State *T) {
  int ret;
  struct lem_mbedtls_drbg *drbg;
  struct lem_mbedtls_conf *conf;
  const char *mode;
  const char *crt = NULL;
  const char *pem = NULL;
  const char *key = NULL;
  const char *keypwd = NULL;
  size_t crt_len = 0;
  size_t pem_len = 0;
  size_t key_len = 0;
  size_t keypwd_len = 0;
  int srv_test_mode = 0;
  int ssl_verify_mode = 0;

  luaL_checktype(T, 1, LUA_TTABLE);

  lua_getfield(T, 1, "mode");
  lua_getfield(T, 1, "drbg");
  lua_getfield(T, 1, "crt");
  lua_getfield(T, 1, "pem");
  lua_getfield(T, 1, "key");
  lua_getfield(T, 1, "keypwd");
  lua_getfield(T, 1, "ssl_verify_mode");
  lua_getfield(T, 1, "srv_test_mode");

  mode = lua_tostring(T, 2);
  drbg = (struct lem_mbedtls_drbg*) lua_touserdata(T, 3);
  crt = lua_tolstring(T, 4, &crt_len);
  pem = lua_tolstring(T, 5, &pem_len);
  key = lua_tolstring(T, 6, &key_len);
  keypwd = lua_tolstring(T, 7, &keypwd_len);
  ssl_verify_mode = lua_tointeger(T, 8);
  srv_test_mode = lua_tointeger(T, 9);

  conf = (struct lem_mbedtls_conf*) lua_newuserdata(T, sizeof(*conf));

  conf->client_or_server_mode = MBEDTLS_SSL_IS_SERVER;

  luaL_getmetatable(T, g_mbedtls_conf_mt);
  lua_setmetatable(T, -2);

  if (mode && (strcmp(mode, "client") == 0)) {
    conf->client_or_server_mode = MBEDTLS_SSL_IS_CLIENT;
  }

  if (conf->client_or_server_mode == MBEDTLS_SSL_IS_SERVER) {
    mbedtls_ssl_cache_init(&conf->cache);
  }

  mbedtls_ssl_config_init(&conf->conf);
  mbedtls_x509_crt_init(&conf->srvcert);
  mbedtls_pk_init(&conf->pkey);


  if (srv_test_mode) {
    if (conf->client_or_server_mode == MBEDTLS_SSL_IS_SERVER) {
      /*
       * 1. Load the certificates and private RSA key 
       *
       * This demonstration program uses embedded test certificates.
       * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
       * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
       */
      ret = mbedtls_x509_crt_parse(&conf->srvcert, (const unsigned char *) mbedtls_test_srv_crt,
          mbedtls_test_srv_crt_len);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - mbedtls_x509_crt_parse returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

      ret = mbedtls_x509_crt_parse(&conf->srvcert, (const unsigned char *) mbedtls_test_cas_pem,
          mbedtls_test_cas_pem_len);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - mbedtls_x509_crt_parse returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

      ret =  mbedtls_pk_parse_key(&conf->pkey, (const unsigned char *) mbedtls_test_srv_key,
          mbedtls_test_srv_key_len, NULL, 0);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - mbedtls_pk_parse_key returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
    }
  } else {
    if (crt) {
      ret = mbedtls_x509_crt_parse(&conf->srvcert, (unsigned char*)crt, crt_len+1);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - crt - mbedtls_x509_crt_parse returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
    }
    if (pem) {
      /* ret = mbedtls_x509_crt_parse_file(&conf->srvcert, pem_file); */
      ret = mbedtls_x509_crt_parse(&conf->srvcert, (unsigned char*)pem, pem_len+1);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - pem - mbedtls_x509_crt_parse returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
    }
    if (key) {
      ret = mbedtls_pk_parse_key(&conf->pkey, (unsigned char*)key, key_len+1/* lua hopefully add a \0 */, (unsigned char*)keypwd, keypwd_len);
      if (ret != 0) {
        char *err;
        err = heap_err_msg("failed - key - mbedtls_pk_parse_key returned -0x%04x", -ret);
        lua_settop(T, 0);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
    }
  }

  /*
   * 4. Setup stuff
   */
  if ((ret = mbedtls_ssl_config_defaults(
          &conf->conf,
          conf->client_or_server_mode,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    char *err;
    err = heap_err_msg("failed - mbedtls_ssl_config_defaults returned -0x%04x", -ret);
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, err);
    free(err);
    return 2;
  }


  mbedtls_ssl_conf_rng(&conf->conf, mbedtls_ctr_drbg_random, &drbg->ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf->conf, lem_mbedtls_debug_callback, stderr);

  mbedtls_ssl_conf_ca_chain(&conf->conf, &conf->srvcert, NULL);

  if (conf->client_or_server_mode == MBEDTLS_SSL_IS_SERVER) {
    mbedtls_ssl_conf_session_cache(&conf->conf, &conf->cache,
        mbedtls_ssl_cache_get,
        mbedtls_ssl_cache_set);
  }

  mbedtls_ssl_conf_authmode(&conf->conf, ssl_verify_mode);


  if ((ret = mbedtls_ssl_conf_own_cert(&conf->conf, &conf->srvcert, &conf->pkey)) != 0) {
    char *err;
    err = heap_err_msg("failed - mbedtls_ssl_conf_own_cert returned -0x%04x", -ret);
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, err);
    free(err);
    return 2;
  }

  return 1;
}

int lem_mbedtls_ssl_context_gc(lua_State *L) {
  struct mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(L, 1);
  mbedtls_ssl_free(ssl);

  return 0;
}

int lem_mbedtls_new_ssl_context(lua_State *T) {
  int ret;
  struct lem_mbedtls_conf *conf = (struct lem_mbedtls_conf*) lua_touserdata(T, 1);
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_newuserdata(T, sizeof(*ssl));

  luaL_getmetatable(T, g_mbedtls_ssl_context_mt);
  lua_setmetatable(T, -2);

  mbedtls_ssl_init(ssl);

  if ((ret = mbedtls_ssl_setup(ssl, &conf->conf)) != 0) {
    char *err;
    err = heap_err_msg("failed - mbedtls_ssl_setup returned -0x%04x", -ret);
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, err);
    free(err);
    return 2;
  }
  return 1;
}

static int lem_mbedtls_ssl_context_reset(lua_State *T) {
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(T, 1);
  mbedtls_ssl_session_reset(ssl);
  
  return 0;
}

struct lem_mbedtls_sock_forward {
  ev_io rssl, wssl;
  ev_io runix, wunix;
  ev_idle idle;

  mbedtls_net_context client_fd;
  mbedtls_ssl_context *ssl;

  unsigned char u_rbuf[4096];
  int u_rlen;

  unsigned char s_rbuf[4096];
  int s_rlen;

  int status;
};

#define NOTHING                0
#define IDLE_CLOSE             1
#define IDLE_REARM_SSL_WATCHER 2
#define IDLE_REARM_UNIX_WATCHER 4

struct lem_mbedtls_ssl_wrap_socket_task {
  struct lem_async a;
  int fd;
  struct lem_mbedtls_sock_forward *event;
  mbedtls_ssl_context *ssl;
  int socket_vector[2];
  int err;
  char *errmsg;
  lua_State *T;
};

#define get_parent_struct(struct_type, field_name, field_addr) \
  ((struct_type*) (((char*)field_addr) - offsetof(struct_type, field_name)))

static void idle_stop_sock_forwarding(EV_P_ ev_idle *w, int revent) {
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, idle, w);

  if (revent != EV_IDLE) {
    /* after a socket error... */

    if (event->status == IDLE_CLOSE) {
      return ;
    } else  {
      int idle_binded = 0;
      if (event->status&(IDLE_REARM_SSL_WATCHER|IDLE_REARM_UNIX_WATCHER)) {
        if (ev_is_active(w)) {
          ev_set_cb(w, idle_stop_sock_forwarding);
          idle_binded = 1;
        }
      }


      if (idle_binded == 0) {
        ev_idle_init(w, idle_stop_sock_forwarding);
        ev_idle_start(EV_A_ w);
      }
      event->status = IDLE_CLOSE;
    }

    ev_io_stop(EV_A_ &event->rssl);
    ev_io_stop(EV_A_ &event->wssl);
    ev_io_stop(EV_A_ &event->runix);
    ev_io_stop(EV_A_ &event->wunix);
    return ;
  }
  close(event->runix.fd);

  /* once we are sure all event are disabled; free the stuff */
  ev_idle_stop(EV_A_ w);
  free(event);
}

static void unix_write_cb(EV_P_ ev_io *w, int revents) {
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, wunix, w);
  int ret;

  (void)revents;

  if (event->status == IDLE_CLOSE) return ;

  if (event->s_rlen == 0) {
    ev_io_stop(EV_A_ w);
    return ;
  }

  ret = write(event->wunix.fd, event->s_rbuf, event->s_rlen);

  if (ret == -1) {
    if (errno == EAGAIN || errno == EINTR) {
      return;
    }
  }

  if (ret <= 0) {
    idle_stop_sock_forwarding(EV_A_ &event->idle, EV_CLEANUP);
    return ;
  }

  event->s_rlen -= ret;

  if (event->s_rlen) {
    memcpy(event->s_rbuf, event->s_rbuf+ret, event->s_rlen);
  } else {
    ev_io_stop(EV_A_ w);
  }
}


static void idle_restart_rssl_watcher(EV_P_ ev_idle *w, int revent) {
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, idle, w);
  (void) revent;

  if (event->status != IDLE_REARM_SSL_WATCHER) return ;

  ev_idle_stop(EV_A_ w);
  ev_io_start(EV_A_ &event->rssl);
  event->status = NOTHING;
}

static void idle_restart_unix_watcher(EV_P_ ev_idle *w, int revent) {
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, idle, w);
  (void) revent;

  if (event->status != IDLE_REARM_UNIX_WATCHER) return ;

  ev_idle_stop(EV_A_ w);
  ev_io_start(EV_A_ &event->runix);
  event->status = NOTHING;
}

static void ssl_forward_cb(EV_P_ ev_io *w, int revents) {
  int ret;
  int len;
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, rssl, w);
  (void)revents;

  if (event->status == IDLE_CLOSE) return ;

  do {
    len = sizeof(event->s_rbuf) - event->s_rlen;

    if (len <= 0) {
      event->status = IDLE_REARM_SSL_WATCHER;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
      ev_idle_init(&event->idle, idle_restart_rssl_watcher);
#pragma GCC diagnostic pop
      ev_idle_start(EV_A_ &event->idle);
      ev_io_stop(EV_A_ w);
      return ;
    }

    ret = mbedtls_ssl_read(event->ssl, event->s_rbuf+event->s_rlen, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      return ;
    }

    if (ret <= 0) {
      /* should be:
       MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
       MBEDTLS_ERR_NET_CONN_RESET
      */
      idle_stop_sock_forwarding(EV_A_ &event->idle, EV_CLEANUP);
      return ;
    }

    event->s_rlen += ret;
    unix_write_cb(EV_A_ &event->wunix, EV_WRITE);
  } while (event->s_rlen == 0);

  ev_io_start(EV_A_ &event->wunix);
}

static void ssl_write_cb(EV_P_ ev_io *w, int revents) {
  int ret;
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, wssl, w);

  (void)revents;

  if (event->status == IDLE_CLOSE) return ;

  if (event->u_rlen == 0) {
    ev_io_stop(EV_A_ w);
    return ;
  }

  ret = mbedtls_ssl_write(event->ssl, event->u_rbuf, event->u_rlen);

  if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
      ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return ;
  }

  if (ret <= 0) {
    idle_stop_sock_forwarding(EV_A_ &event->idle, EV_CLEANUP);
    return ;
  }

  event->u_rlen -= ret;

  if (event->u_rlen) {
    memcpy(event->u_rbuf, event->u_rbuf+ret, event->u_rlen);
  } else {
    ev_io_stop(EV_A_ w);
  }
}

static void unix_forward_cb(EV_P_ ev_io *w, int revents) {
  int ret;
  struct lem_mbedtls_sock_forward *event =
    get_parent_struct(struct lem_mbedtls_sock_forward, runix, w);
  int len;

  (void)revents;

  if (event->status == IDLE_CLOSE) return ;

  do {
    len = sizeof(event->u_rbuf) - event->u_rlen;

    if (len <= 0) {
      event->status = IDLE_REARM_UNIX_WATCHER;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
      ev_idle_init(&event->idle, idle_restart_unix_watcher);
#pragma GCC diagnostic pop
      ev_idle_start(EV_A_ &event->idle);
      ev_io_stop(EV_A_ w);
      return ;
    }


    ret = read(w->fd, event->u_rbuf, len);

    if (ret == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        return ;
      }
    }

    if (ret <= 0) {
      idle_stop_sock_forwarding(EV_A_ &event->idle, EV_CLEANUP);
      return ;
    }

    event->u_rlen += ret;

    ssl_write_cb(EV_A_ &event->wssl, EV_WRITE);
  } while (event->u_rlen == 0);

  ev_io_start(EV_A_ &event->wssl);
}


void lem_mbedtls_ssl_wrap_socket_work(struct lem_async *a) {
  int ret;
  struct lem_mbedtls_ssl_wrap_socket_task *task = (struct lem_mbedtls_ssl_wrap_socket_task*)a;
  struct lem_mbedtls_sock_forward *event = (struct lem_mbedtls_sock_forward*) lem_xmalloc(sizeof *event);
  mbedtls_ssl_context *ssl = task->ssl;
  mbedtls_net_context *client_fd = &event->client_fd;

  event->ssl = ssl;
  event->s_rlen = 0;
  event->u_rlen = 0;
  event->status = 0;

  task->event = event;

  mbedtls_net_init(client_fd);
  client_fd->fd = task->fd;

  mbedtls_ssl_set_bio(ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      task->err = ret;
      task->errmsg = heap_err_msg("failed - mbedtls_ssl_handshake returned -0x%04x", -ret);
      return ;
    }
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, task->socket_vector) == -1) {
    task->err = -errno;
    task->errmsg = heap_err_msg("failed socketpair: %s", strerror(errno));
    return ;
  }

  if (fcntl(task->socket_vector[0], F_SETFL, O_NONBLOCK) == -1) {
    task->err = -errno;
    task->errmsg = heap_err_msg("failed fcntl socket[0]: %s", strerror(errno));
    return ;
  }

  if (fcntl(task->socket_vector[0], F_SETFD, FD_CLOEXEC) == -1) {
    task->err = -errno;
    task->errmsg = heap_err_msg("failed fcntl socket[0]: %s", strerror(errno));
    return ;
  }

  if (fcntl(task->socket_vector[1], F_SETFL, O_NONBLOCK) == -1) {
    task->err = -errno;
    task->errmsg = heap_err_msg("failed fcntl: socket[1]: %s", strerror(errno));
    return ;
  }

  if (fcntl(task->socket_vector[1], F_SETFD, FD_CLOEXEC) == -1) {
    task->err = -errno;
    task->errmsg = heap_err_msg("failed fcntl: socket[1]: %s", strerror(errno));
    return ;
  }
}

void lem_mbedtls_ssl_wrap_socket_reap(struct lem_async *a) {
  struct lem_mbedtls_ssl_wrap_socket_task *task = (struct lem_mbedtls_ssl_wrap_socket_task*)a;
  struct lem_mbedtls_sock_forward *event = task->event;
  lua_State *T = task->T;


  if (task->err) {
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, task->errmsg);

    lem_queue(T, 2);

    free(task->errmsg);
    free(event);
    free(task);

    return ;
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
  ev_io_init(&event->rssl, ssl_forward_cb, task->fd, EV_READ);
  ev_io_init(&event->wssl, ssl_write_cb, task->fd, EV_WRITE);

  ev_io_init(&event->runix, unix_forward_cb, task->socket_vector[0], EV_READ);
  ev_io_init(&event->wunix, unix_write_cb, task->socket_vector[0], EV_WRITE);
#pragma GCC diagnostic pop

  ev_io_start(LEM_ &event->rssl);
  ev_io_start(LEM_ &event->runix);

  lua_settop(T, 0);
  lua_pushinteger(T, task->socket_vector[1]);
  lem_queue(T, 1);

  free(task);
}

static int lem_mbedtls_ssl_wrap_socket(lua_State *T) {
  struct lem_mbedtls_ssl_wrap_socket_task *task = (struct lem_mbedtls_ssl_wrap_socket_task*) lem_xmalloc(sizeof *task);
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(T, 1);

  task->err = 0;
  task->errmsg = NULL;
  task->fd = lua_tointeger(T, 2); 
  task->ssl = ssl;
  task->T = T;

  lem_async_do(&task->a, lem_mbedtls_ssl_wrap_socket_work, lem_mbedtls_ssl_wrap_socket_reap);

  return lua_yield(T, 2);
}


static int lem_mbedtls_ssl_verify(lua_State *T) {
  int flags;
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(T, 1);
  if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
    lua_pushboolean(T, 0);
    return 1;
  }
  lua_pushboolean(T, 1);
  return 1;
}

static int lem_mbedtls_ssl_set_hostname(lua_State *T) {
  int ret;
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(T, 1);
  if ((ret = mbedtls_ssl_set_hostname(ssl, lua_tostring(T, 2))) != 0) {
    char *err;
    err = heap_err_msg("failed - mbedtls_ssl_set_hostname returned -0x%04x", -ret);
    lua_settop(T, 0);
    lua_pushboolean(T, 0);
    lua_pushstring(T, err);
    free(err);
    return 2;
  }
  lua_pushboolean(T, 1);
  return 1;
}


static int lem_mbedtls_ssl_close_notify(lua_State *T) {
  int ret;
  mbedtls_ssl_context *ssl = (mbedtls_ssl_context*) lua_touserdata(T, 1);

  while ((ret = mbedtls_ssl_close_notify(ssl)) < 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
      char *err;
      err = heap_err_msg("failed - mbedtls_close_notify returned -0x%04x", -ret);
      lua_settop(T, 0);
      lua_pushboolean(T, 0);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }
  }
  lua_pushboolean(T, 1);
  return 1;
}

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE         4096
#define DFL_FORMAT              FORMAT_PEM

struct lem_mbedtls_new_pkey_task {
  struct lem_async a;
  lua_State *T;
  int pkey_type;
  int rsa_keysize;
  int ec_curve;
  int format;
  struct lem_mbedtls_drbg *drbg;

  int err;
  char *outbuf;
  size_t outbuf_len;
};

static void lem_mbedtls_new_pkey_work(struct lem_async *a) {
  int ret;
  mbedtls_pk_context key;
  struct lem_mbedtls_new_pkey_task *task = (struct lem_mbedtls_new_pkey_task*)a;

  mbedtls_pk_init(&key);

  if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)task->pkey_type)) != 0)) {
    task->err = -1;
    task->outbuf = heap_err_msg("failed - mbedtls_pk_setup returned -0x%04x", -ret);
    return ;
  }

  if (task->pkey_type == MBEDTLS_PK_RSA) {
    ret = mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(key),
            mbedtls_ctr_drbg_random,
            &task->drbg->ctr_drbg, task->rsa_keysize, 65537);

    if (ret != 0) {
      task->err = -2;
      task->outbuf = heap_err_msg("failed - mbedtls_rsa_gen_key returned -0x%04x", -ret);
      return ;
    }
  } else if (task->pkey_type == MBEDTLS_PK_ECKEY) {
    ret = mbedtls_ecp_gen_key((mbedtls_ecp_group_id) task->ec_curve, mbedtls_pk_ec(key),
            mbedtls_ctr_drbg_random, &task->drbg->ctr_drbg);
    if (ret != 0) {
      task->err = -3;
      task->outbuf = heap_err_msg("failed - mbedtls_ecp_gen_key returned -0x%04x", -ret);
      return ;
    }
  }

  {
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, sizeof output_buf);

    if (task->format == FORMAT_PEM) {
      if ((ret = mbedtls_pk_write_key_pem(&key, output_buf, sizeof output_buf)) != 0) {
        task->err = -4;
        task->outbuf = heap_err_msg("failed - mbedtls_pk_write_key_pem returned -0x%04x", -ret);
        return ;
      }
      len = strlen((char *) output_buf);
    } else {
      if ((ret = mbedtls_pk_write_key_der(&key, output_buf, sizeof output_buf)) < 0) {
        task->err = -5;
        task->outbuf = heap_err_msg("failed - mbedtls_pk_write_key_der returned -0x%04x", -ret);
        return ;
      }
      len = ret;
      c = output_buf + sizeof(output_buf) - len;
    }

    task->outbuf = (char*)lem_xmalloc(len);
    task->outbuf_len = len;

    memcpy(task->outbuf, c, len);

    return ;
  }
}

static void lem_mbedtls_new_pkey_reap(struct lem_async *a) {
  struct lem_mbedtls_new_pkey_task *task = (struct lem_mbedtls_new_pkey_task*)a;
  lua_State *T = task->T;

  if (task->err) {
    lua_settop(T, 0);
    lua_pushnil(T);
    lua_pushstring(T, task->outbuf);

    lem_queue(T, 2);

    free(task->outbuf);
    free(task);
    return ;
  }


  lua_settop(T, 0);
  lua_pushlstring(T, task->outbuf, task->outbuf_len);
  lem_queue(T, 1);
  free(task->outbuf);
  free(task);
  return ;
}

static int lem_mbedtls_new_pkey(lua_State *T) {
  const mbedtls_ecp_curve_info *curve_info;

  const char *opt;
  struct lem_mbedtls_new_pkey_task *task = (struct lem_mbedtls_new_pkey_task*) lem_xmalloc(sizeof(*task));

  task->pkey_type = DFL_TYPE;
  task->rsa_keysize = 4096;
  task->ec_curve = 0;
  task->format = DFL_FORMAT;
  task->err = 0;


  luaL_checktype(T, 1, LUA_TTABLE);

  lua_getfield(T, 1, "drbg");
  lua_getfield(T, 1, "type");
  lua_getfield(T, 1, "format");
  lua_getfield(T, 1, "rsa_keysize");
  lua_getfield(T, 1, "ec_curve");

  task->drbg = (struct lem_mbedtls_drbg*) lua_touserdata(T, 2);

  opt = lua_tostring(T, 3);
  if (opt != NULL) {
    if (strcmp(opt, "rsa") == 0) {
      task->pkey_type = MBEDTLS_PK_RSA;
    } else if (strcmp(opt, "ec") == 0) {
      task->pkey_type = MBEDTLS_PK_ECKEY;
    } else {
      lua_pushnil(T);
      lua_pushliteral(T, "type need to be rsa|ec");
      free(task);
      return 2;
    }
  }

  opt = lua_tostring(T, 4);
  if (opt != NULL) {
    if (strcmp(opt, "pem") == 0) {
      task->format = FORMAT_PEM;
    } else if (strcmp(opt, "der") == 0) {
      task->format = FORMAT_DER;
    } else {
      lua_pushnil(T);
      lua_pushliteral(T, "oops - format need to be: pem|der");
      free(task);
      return 2;
    }
  }

  task->rsa_keysize = lua_tointeger(T, 5);

  if (task->rsa_keysize < 1024) {
    task->rsa_keysize = DFL_RSA_KEYSIZE;
  } else if (task->rsa_keysize > MBEDTLS_MPI_MAX_BITS) {
    char *err = heap_err_msg("oops - maximum rsa_keysize is %d", MBEDTLS_MPI_MAX_BITS);
    lua_pushnil(T);
    lua_pushstring(T, err);
    free(task);
    free(err);
    return 2;
  }

  opt = lua_tostring(T, 6);

  if (opt != NULL) {
    curve_info = mbedtls_ecp_curve_info_from_name(opt);

    if (curve_info == NULL) {
      lua_pushnil(T);
      lua_pushliteral(T, "oops - ec_curve is invalid");
      free(task);
      return 2;
    } else {
      task->ec_curve = curve_info->grp_id;
    }
  }

  task->T = T;
  lem_async_do(&task->a, lem_mbedtls_new_pkey_work, lem_mbedtls_new_pkey_reap);

  return lua_yield(T, 0);
}

static int lem_mbedtls_new_cert(lua_State *T) {
  int ret;
  mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
  mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                     *subject_key = &loaded_subject_key;

  mbedtls_x509_crt issuer_crt;
  mbedtls_x509write_cert crt;
  mbedtls_x509_csr csr;
  mbedtls_mpi serial;
  struct lem_mbedtls_drbg *drbg;

  mbedtls_x509write_crt_init(&crt);
  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
  mbedtls_pk_init(&loaded_issuer_key);
  mbedtls_pk_init(&loaded_subject_key);
  mbedtls_mpi_init(&serial);
  mbedtls_x509_csr_init(&csr);
  mbedtls_x509_crt_init(&issuer_crt);

  luaL_checktype(T, 1, LUA_TTABLE);

  lua_getfield(T, 1, "drbg");
  lua_getfield(T, 1, "serial");
  lua_getfield(T, 1, "selfsign");
  lua_getfield(T, 1, "issuer_crt");
  lua_getfield(T, 1, "csr");
  lua_getfield(T, 1, "subject_pwd");
  lua_getfield(T, 1, "subject_key");
  lua_getfield(T, 1, "issuer_pwd");
  lua_getfield(T, 1, "issuer_key");
  lua_getfield(T, 1, "subject_name");
  lua_getfield(T, 1, "issuer_name");
  lua_getfield(T, 1, "not_before");
  lua_getfield(T, 1, "not_after");
  lua_getfield(T, 1, "is_ca");
  lua_getfield(T, 1, "max_pathlen");
  lua_getfield(T, 1, "key_usage");
  lua_getfield(T, 1, "ns_cert_type");

  drbg = (struct lem_mbedtls_drbg*)lua_touserdata(T, 2);

  {
    char issuer_name_buf[256];
    char subject_name_buf[256];
    const char *c_subject_name;
    const char *c_issuer_name;
    const char *c_issuer_crt;
    size_t c_issuer_crt_len = 0;
    const char *c_subject_pwd;
    size_t c_subject_pwd_len = 0;
    const char *c_csr;
    size_t c_csr_len = 0;
    const char *c_subject_key;
    size_t c_subject_key_len = 0;
    const char *c_issuer_pwd;
    size_t c_issuer_pwd_len = 0;
    const char *c_issuer_key;
    size_t c_issuer_key_len = 0;
    const char *c_not_before = "20010101000000";
    const char *c_not_after = "20301231235959";
    const char *c_serial;
    int c_selfsign = 0;
    int c_is_ca = 0;
    int c_max_pathlen = -1;
    int c_key_usage = 0;
    int c_ns_cert_type = 0;

    const char *temp;

    c_serial = lua_tostring(T, 3);
    if (c_serial == NULL) {
      c_serial = "1";
    }

    if ((ret = mbedtls_mpi_read_string(&serial, 10, c_serial)) != 0) {
      char *err;
      err = heap_err_msg("failed - serial - mbedtls_mpi_read_string returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    c_selfsign = lua_tointeger(T, 4);

    c_issuer_crt = lua_tolstring(T, 5, &c_issuer_crt_len);

    if (!c_selfsign && c_issuer_crt) {
      if ((ret = mbedtls_x509_crt_parse(&issuer_crt, (unsigned char *)c_issuer_crt, c_issuer_crt_len+1)) != 0) {
        char *err = heap_err_msg("failed - issuer_crt_file - mbedtls_x509_crt_parse returned -0x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

      ret = mbedtls_x509_dn_gets(issuer_name_buf, sizeof(issuer_name_buf), &issuer_crt.subject);
      if (ret < 0) {
        char *err = heap_err_msg("failed - mbedtls_x509_dn_gets returned -0x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
      c_issuer_name = issuer_name_buf;
    }

    c_csr = lua_tolstring(T, 6, &c_csr_len);

    if (!c_selfsign && c_csr) {
      if ((ret = mbedtls_x509_csr_parse(&csr, (unsigned char*)c_csr, c_csr_len+1)) != 0) {
        char *err = heap_err_msg("failed - mbedtls_x509_csr_parse returned -0x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

      ret = mbedtls_x509_dn_gets(subject_name_buf, sizeof(subject_name_buf), &csr.subject);
      if (ret < 0) {
        char *err = heap_err_msg("failed - mbedtls_x509_dn_gets returned -0x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

      c_subject_name = subject_name_buf;
      subject_key = &csr.pk;
    }

    c_subject_pwd = lua_tolstring(T, 7, &c_subject_pwd_len);

    if (c_subject_pwd == NULL) {
      c_subject_pwd = "";
      c_subject_pwd_len = 0;
    } else {
      c_subject_pwd_len += 1;
    }

    c_subject_key = lua_tolstring(T, 8, &c_subject_key_len);

    if (!c_selfsign && c_subject_key) {
      ret = mbedtls_pk_parse_key(&loaded_subject_key, (unsigned char*)c_subject_key, c_subject_key_len+1, (unsigned char*)c_subject_pwd, c_subject_pwd_len);
      if (ret != 0) {
        char *err = heap_err_msg("failed - c_subject_key - mbedtls_pk_parse_keyfile returned -0x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }
    }

    c_issuer_pwd = lua_tolstring(T, 9, &c_issuer_pwd_len);

    if (c_issuer_pwd == NULL) {
      c_issuer_pwd = "";
      c_issuer_pwd_len = 0;
    } else {
      c_issuer_pwd_len += 1;
    }

    c_issuer_key = lua_tolstring(T, 10, &c_issuer_key_len);

    if (c_issuer_key) {
      ret = mbedtls_pk_parse_key(&loaded_issuer_key, (unsigned char*)c_issuer_key, c_issuer_key_len+1, (unsigned char*)c_issuer_pwd, c_issuer_pwd_len);
      if (ret != 0) {
        char *err = heap_err_msg("failed - issuer_key - mbedtls_pk_parse_keyfile returned -x%04x", -ret);
        lua_pushnil(T);
        lua_pushstring(T, err);
        free(err);
        return 2;
      }

    } else {
      lua_pushnil(T);
      lua_pushliteral(T, "no issuer key set");
      return 2;
    }

    temp = lua_tostring(T, 11);
    if (temp) {
      c_subject_name = temp;
    }

    temp = lua_tostring(T, 12);
    if (temp) {
      c_issuer_name = temp;
    }

    temp = lua_tostring(T, 13);
    if (temp) {
      c_not_before = temp;
    }

    temp = lua_tostring(T, 14);
    if (temp) {
      c_not_after = temp;
    }

    c_is_ca = lua_tointeger(T, 15);

    if (lua_isnil(T, 16) == 0) {
      c_max_pathlen = lua_tointeger(T, 16);
    }

    c_key_usage = lua_tointeger(T, 17);
    c_ns_cert_type = lua_tointeger(T, 18);

    if (c_issuer_crt) {
      if (!mbedtls_pk_can_do(&issuer_crt.pk, MBEDTLS_PK_RSA) ||
          mbedtls_mpi_cmp_mpi(&mbedtls_pk_rsa(issuer_crt.pk)->N,
            &mbedtls_pk_rsa(*issuer_key)->N) != 0 ||
          mbedtls_mpi_cmp_mpi(&mbedtls_pk_rsa(issuer_crt.pk)->E,
            &mbedtls_pk_rsa(*issuer_key)->E) != 0) {
        lua_pushnil(T);
        lua_pushliteral(T, "failed - issuer_key does not match issuer certificate");
        return 2;
      }
    }

    if (c_key_usage)
      mbedtls_x509write_crt_set_key_usage(&crt, c_key_usage);

    if (c_ns_cert_type)
      mbedtls_x509write_crt_set_ns_cert_type(&crt, c_ns_cert_type);

    if (c_selfsign) {
      c_subject_name = c_issuer_name;
      subject_key = issuer_key;
    }

    mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);


    /* write the crt file */
    if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, c_subject_name)) != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_subject_name returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, c_issuer_name)) != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_issuer_name returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_serial returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    ret = mbedtls_x509write_crt_set_validity(&crt, c_not_before, c_not_after);
    if (ret != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_validity returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    /* Basic Constraints extension */
    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, c_is_ca, c_max_pathlen);
    if (ret != 0) {
      char *err = heap_err_msg("failed - x509write_crt_set_basic_contraints returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
    if (ret != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_subject_key_identifier returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }

    ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
    if (ret != 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_authority_key_identifier returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }
  }

  {
    unsigned char output_buf[4096];
    if ((ret = mbedtls_x509write_crt_pem(&crt, output_buf, 4096, mbedtls_ctr_drbg_random, &drbg->ctr_drbg)) < 0) {
      char *err = heap_err_msg("failed - mbedtls_x509write_crt_set_authority_key_identifier returned -0x%04x", -ret);
      lua_pushnil(T);
      lua_pushstring(T, err);
      free(err);
      return 2;
    }
    lua_pushstring(T, (const char*)output_buf);
    return 1;
  }
}

int lem_mbedtls_debug_set_threshold(lua_State *L) {
  mbedtls_debug_set_threshold(lua_tointeger(L, -1));
  return 0;
}

static struct const_list {
  char *key;
  int v;
} opt_key_usage_list[] =
{
  {"digital_signature", MBEDTLS_X509_KU_DIGITAL_SIGNATURE},
  {"non_repudiation", MBEDTLS_X509_KU_NON_REPUDIATION},
  {"key_encipherment", MBEDTLS_X509_KU_KEY_ENCIPHERMENT},
  {"data_encipherment", MBEDTLS_X509_KU_DATA_ENCIPHERMENT},
  {"key_agreement", MBEDTLS_X509_KU_KEY_AGREEMENT},
  {"key_cert_sign", MBEDTLS_X509_KU_KEY_CERT_SIGN},
  {"crl_sign", MBEDTLS_X509_KU_CRL_SIGN},
},
 opt_ns_cert_type_list[] = {
  {"ssl_client", MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT},
  {"ssl_server", MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER},
  {"email", MBEDTLS_X509_NS_CERT_TYPE_EMAIL},
  {"object_signing", MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING},
  {"ssl_ca", MBEDTLS_X509_NS_CERT_TYPE_SSL_CA},
  {"email_ca", MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA},
  {"object_signing_ca", MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA},
} ;

int luaopen_lem_mbedtls_core(lua_State *L) {
  int i;

  /* metatable for drbg object */
  luaL_newmetatable(L, g_mbedtls_drbg_mt);

  lua_pushcfunction(L, lem_mbedtls_drbg_gc);
  lua_setfield(L, -2, "__gc");

  /* metatable for config object */
  luaL_newmetatable(L, g_mbedtls_conf_mt);

  lua_pushcfunction(L, lem_mbedtls_conf_gc);
  lua_setfield(L, -2, "__gc");

  /* metatable for ssl context object */
  luaL_newmetatable(L, g_mbedtls_ssl_context_mt);

  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");

  lua_pushcfunction(L, lem_mbedtls_ssl_wrap_socket);
  lua_setfield(L, -2, "wrap_socket");

  lua_pushcfunction(L, lem_mbedtls_ssl_context_reset);
  lua_setfield(L, -2, "reset");

  lua_pushcfunction(L, lem_mbedtls_ssl_set_hostname);
  lua_setfield(L, -2, "set_hostname");

  lua_pushcfunction(L, lem_mbedtls_ssl_verify);
  lua_setfield(L, -2, "verify");

  lua_pushcfunction(L, lem_mbedtls_ssl_close_notify);
  lua_setfield(L, -2, "close_notify");

  lua_pushcfunction(L, lem_mbedtls_ssl_context_gc);
  lua_setfield(L, -2, "__gc");


  /* lem.mbedtls.core module global table */
  lua_newtable(L);

  lua_pushcfunction(L, lem_mbedtls_new_drbg);
  lua_setfield(L, -2, "new_drbg");

  lua_pushcfunction(L, lem_mbedtls_new_conf);
  lua_setfield(L, -2, "new_conf");

  lua_pushcfunction(L, lem_mbedtls_new_ssl_context);
  lua_setfield(L, -2, "new_ssl_context");

  lua_pushcfunction(L, lem_mbedtls_new_pkey);
  lua_setfield(L, -2, "new_pkey");

  lua_pushcfunction(L, lem_mbedtls_new_cert);
  lua_setfield(L, -2, "new_cert");

  lua_pushcfunction(L, lem_mbedtls_debug_set_threshold);
  lua_setfield(L, -2, "mbedtls_debug_set_threshold");

#ifndef COUNT_OF
#define COUNT_OF(x) (sizeof(x)/sizeof(x[0]))
#endif

  lua_newtable(L);
  for (i=0;i<COUNT_OF(opt_key_usage_list);i++) {
    lua_pushinteger(L, opt_key_usage_list[i].v);
    lua_setfield(L, -2, opt_key_usage_list[i].key);
  }
  lua_setfield(L, -2, "opt_key_usage_map");

  lua_newtable(L);
  for (i=0;i<COUNT_OF(opt_ns_cert_type_list);i++) {
    lua_pushinteger(L, opt_ns_cert_type_list[i].v);
    lua_setfield(L, -2, opt_ns_cert_type_list[i].key);
  }
  lua_setfield(L, -2, "opt_ns_cert_type_map");
#undef COUNT_OF

  return 1;
}
