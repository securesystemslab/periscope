#ifndef _UAPI_LINUX_ASHMEM_H
#define _UAPI_LINUX_ASHMEM_H

#include <sys/ioctl.h>
#include <sys/mman.h>

#define ASHMEM_NAME_LEN 256
#define ASHMEM_NAME_DEF "dev/ashmem"
#define ASHMEM_NOT_PURGED 0
#define ASHMEM_WAS_PURGED 1
#define ASHMEM_IS_UNPINNED 0
#define ASHMEM_IS_PINNED 1
struct ashmem_pin {
  u32 offset;
  u32 len;
};
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)

static int fd = 0;
static void *addr = NULL;
static size_t size;

static int shm_remove(int shmid) {
  if (addr != NULL) {
    munmap(addr, size);
    addr = NULL;
  }

  if (fd == 0) return -1;
  close(fd);
  fd = 0;
  return 0;
}

int ashmget(key_t key, size_t sz, int flags) {
  if (fd != 0) return -1;

  fd = open("/dev/ashmem", O_RDWR);
  size = sz;
  ioctl(fd, ASHMEM_SET_SIZE, size);
  return fd;
}

void *ashmat(int shmid, const void *shmaddr, int shmflg) {
  addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  return addr;
}

int ashmctl(int shmid, int cmd, void *buf) {
  if (cmd == IPC_RMID) {
    return shm_remove(shmid);
  }
#if 0
  else if (cmd == IPC_STAT) {
    // TODO
  }
#endif
  errno = EINVAL;
  return -1;
}
#endif
