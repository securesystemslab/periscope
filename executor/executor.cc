#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/types.h>
#endif

#define KCOV_INIT_HWIOTRACE _IOR('c', 2, unsigned long)
#define KCOV_ENABLE_HWIOTRACE _IO('c', 102)
#define KCOV_DISABLE_HWIOTRACE _IO('c', 103)

#define KFUZ_INIT _IOR('c', 1, unsigned long)
#define KFUZ_CONSUME_ENABLE _IO('c', 100)
#define KFUZ_CONSUME_CHECK _IO('c', 101)
#define KFUZ_CONSUME_DISABLE _IO('c', 102)

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

void *init_afl() {
  char *shm_str = getenv("__AFL_SHM_ID");
  if (!shm_str) {
    return NULL;
  }

  int shm_id;
  sscanf(shm_str, "%d", &shm_id);

  void *area = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_id, 0);

  memset(area, 0, MAP_SIZE);

  return area;
}

#define TEST_AFL 0

int default_coverage(void *area) {
  if (area == NULL) {
    return -1;
  }

  (*((int *)area))++;

#if TEST_AFL  // Fake coverage for testing AFL
  srand(time(NULL));
  (*((int *)area + (rand() % MAP_SIZE / sizeof(int))))++;
#endif

  return 0;
}

void exit_afl(void *area) {
  default_coverage(area);

  munmap(area, MAP_SIZE);
}

void *init_kcov(int &fd) {
  void *area = NULL;

  fd = open("/sys/kernel/debug/kcov", O_RDWR);
  if (fd == -1) {
    goto open_fail;
  }

  if (ioctl(fd, KCOV_INIT_HWIOTRACE, MAP_SIZE / sizeof(unsigned long)) != 0) {
    goto ioctl_fail;
  }

  area = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (area == MAP_FAILED) {
    goto ioctl_fail;
  }

  return area;

ioctl_fail:
  close(fd);
  fd = -1;

open_fail:
  return NULL;
}

int enable_kcov(int fd) {
  if (ioctl(fd, KCOV_ENABLE_HWIOTRACE, 0) != 0) return -1;
  return 0;
}

int disable_kcov(int fd) {
  if (ioctl(fd, KCOV_DISABLE_HWIOTRACE, 0) != 0) return -1;
  return 0;
}

void exit_kcov(int fd, void *area) {
  /*
  if (area != NULL) {
    munmap(area, MAP_SIZE);
  }
  */
  close(fd);
}

void *init_kfuz(int &fd, char *file_buf, int file_size) {
  void *area = NULL;
  int page_size = getpagesize();
  int area_size =
      (file_size + page_size - 1) & (~(page_size - 1));  // page-aligned

  fd = open("/sys/kernel/debug/kfuz", O_RDWR);
  if (fd == -1) {
    goto open_fail;
  }

  if (ioctl(fd, KFUZ_INIT, area_size) != 0) {
    goto ioctl_fail;
  }

  area = mmap(NULL, area_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (area == MAP_FAILED) {
    goto ioctl_fail;
  }

  memset(area, 0xab, area_size);
  memcpy(area, file_buf, file_size);

  return area;

ioctl_fail:
  close(fd);
  fd = -1;

open_fail:
  return NULL;
}

int enable_kfuz(int fd) {
  if (ioctl(fd, KFUZ_CONSUME_ENABLE, 0) != 0) return -1;
  return 0;
}

long check_kfuz(int fd) { return ioctl(fd, KFUZ_CONSUME_CHECK, 0); }

int disable_kfuz(int fd) {
  if (ioctl(fd, KFUZ_CONSUME_DISABLE, 0) != 0) return -1;
  return 0;
}

void exit_kfuz(int fd) { close(fd); }

char *read_file(char *path, int &size) {
  FILE *file = fopen(path, "r");
  if (file == NULL) return NULL;

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (size <= 0) {
    printf("empty input file\n");
    return NULL;
  }

  char *file_buf = (char *)malloc(size);
  if (file_buf == NULL) return NULL;

  fread(file_buf, sizeof(char), size, file);

  int fd = fileno(file);
  fsync(fd);

  fclose(file);

  return file_buf;
}

bool check_invalid_length(int input_size) {
#ifdef QCACLD_3_0
  if (check_invalid_length_qcacld_3_0(input_size)) {
    return true;
  }
#endif
  return false;
}

bool check_blacklist(char *input_buf, int input_size) {
  glob_t globbuf;

  // Exact-match-based automatic input filtering
  glob("/data/local/tmp/out/blacklist/*.cur_input", 0, NULL, &globbuf);

  for (unsigned i = 0; i < globbuf.gl_pathc; i++) {
    const char *path = globbuf.gl_pathv[i];
    FILE *file = fopen(path, "r");
    if (file != NULL) {
      fseek(file, 0, SEEK_END);
      int size = ftell(file);
      fseek(file, 0, SEEK_SET);

      if (size == input_size) {
        char *file_buf = (char *)malloc(size);
        if (file_buf != NULL) {
          fread(file_buf, sizeof(char), size, file);
          if (memcmp(file_buf, input_buf, size) == 0) {
            free(file_buf);
            fclose(file);
            return true;
          }
          free(file_buf);
        }
      }
      fclose(file);
    }
  }
  return false;
}

#define FF(_b) (0xff << ((_b) << 3))

static u32 count_bytes(u8 *mem) {
  u32 *ptr = (u32 *)mem;
  u32 i = (MAP_SIZE >> 2);
  u32 ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;
  }

  return ret;
}

#define MAX_POLL_COUNT 1000
#define MAX_MSG_COUNT 4

void raise_interrupts() {
  // For WiFi, let's use ping utility
  printf("raising interrupt\n");

  pid_t pid = fork();
  if (pid == 0) {  // child
    execl("/system/bin/ping", "ping", "-c", "1", "ndss-symposium.org",
          (char *)NULL);
  }

  int status;
  waitpid(pid, &status, 0);
}

/*
 * variables used by signal handler
 */
static int kfuz_fd;
static int kcov_fd;

static void handle_stop_sig(int sig) {
  disable_kfuz(kfuz_fd);
  exit_kfuz(kfuz_fd);

  disable_kcov(kcov_fd);
  exit_kcov(kcov_fd, NULL);
}

static void setup_signal_handlers(void) {
  struct sigaction sa;

  sa.sa_handler = NULL;
  sa.sa_flags = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
}

#define INTERRUPT_TEST 0

int main(int argc, char *argv[]) {
  int ret = 0;
  int file_size;
  char *file_buf = NULL;
  void *aflcov_area = NULL;
  void *kfuz_area = NULL;
  void *kcov_area = NULL;
  int poll_remaining_cnt = MAX_POLL_COUNT;
  int msg_remaining_cnt = MAX_MSG_COUNT;  // To prevent input getting too large
  bool blacklisted = false;

  setup_signal_handlers();

  aflcov_area = init_afl();

#if INTERRUPT_TEST
  while (poll_remaining_cnt > 0) {
    raise_interrupts();
    poll_remaining_cnt--;
  }
  return 0;
#endif

  if (argc < 2) {
    ret = -1;
    goto afl_input_invalid;
  }

  file_buf = read_file(argv[1], file_size);
  if (file_buf == NULL) {
    ret = -1;
    goto afl_input_invalid;
  }

  if (file_size > getpagesize()) {
    ret = -1;
    goto afl_input_invalid;
  }

  if (check_invalid_length(file_size)) {
    ret = -1;
    goto afl_input_invalid;
  }

  blacklisted = check_blacklist(file_buf, file_size);
  if (blacklisted) {
    goto afl_input_invalid;
  }

  kfuz_area = init_kfuz(kfuz_fd, file_buf, file_size);
  if (kfuz_area == NULL) {
    ret = -1;
    goto kfuz_init_fail;
  }

  kcov_area = init_kcov(kcov_fd);
  if (kcov_area == NULL) {
    ret = -1;
    goto kcov_init_fail;
  }

  if (enable_kcov(kcov_fd) == 0) {
    long total_consumed_bytes = 0;

    while (msg_remaining_cnt > 0 && file_size - total_consumed_bytes >= 4) {
      long consumed_bytes = 0;

      if (total_consumed_bytes > 0 &&
          check_invalid_length(file_size - total_consumed_bytes)) {
        break;
      }

      blacklisted |=
          check_blacklist((char *)kfuz_area, file_size - total_consumed_bytes);

      if (blacklisted) {
        break;
      }

      if (enable_kfuz(kfuz_fd) == 0) {
        while (poll_remaining_cnt > 0 && consumed_bytes <= 0) {
          raise_interrupts();

          consumed_bytes = check_kfuz(kfuz_fd);

          poll_remaining_cnt--;
        }

        disable_kfuz(kfuz_fd);
      }

      if (consumed_bytes > 0) {
        // Shift yet-to-consume data towards the beginning
        if (consumed_bytes < file_size - total_consumed_bytes) {
          for (int i = consumed_bytes; i < file_size - total_consumed_bytes;
               i++) {
            char *area = (char *)kfuz_area;

            area[i - consumed_bytes] = area[i];
          }
        }

#define TRACE_KCOV 1
#if TRACE_KCOV
        printf("kcov: byte count=%u\n", count_bytes((u8 *)kcov_area));
#endif

        if (aflcov_area != NULL && kcov_area != NULL) {
          for (unsigned i = 0; i < MAP_SIZE; i++) {
            u8 *dst = (u8 *)aflcov_area;
            u8 *src = (u8 *)kcov_area;

            dst[i] += src[i];
          }
        }
      }

      total_consumed_bytes += consumed_bytes;

      printf("consumed %ld bytes (%ld/%d bytes)\n", consumed_bytes,
             total_consumed_bytes, file_size);

      msg_remaining_cnt--;
    }

    disable_kcov(kcov_fd);
  }

  exit_kcov(kcov_fd, kcov_area);

kcov_init_fail:

  exit_kfuz(kfuz_fd);

kfuz_init_fail:
afl_input_invalid:

  if (file_buf != NULL) {
    free(file_buf);
  }

  if (aflcov_area != NULL) {
    exit_afl(aflcov_area);
  }

  if (blacklisted) {
    assert(!blacklisted && "Current input has been blacklisted!");
  }

  return ret;
}
