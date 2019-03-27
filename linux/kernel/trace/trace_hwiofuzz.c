/*
 * HW I/O fuzzing
 */

#define pr_fmt(fmt) "hwiofuzz: " fmt

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#define HWIOFUZZ_PER_CTX_STATIC 1
#define HWIOFUZZ_PER_IRQ_DYNAMIC 2

#define HWIOFUZZ_MAPPING HWIOFUZZ_PER_IRQ_DYNAMIC

/*
 * Must be synchronized with the executor program
 */
#define HWIOFUZZ_INIT _IOR('c', 1, unsigned long)
#define HWIOFUZZ_CONSUME_ENABLE _IO('c', 100)
#define HWIOFUZZ_CONSUME_CHECK _IO('c', 101)
#define HWIOFUZZ_CONSUME_DISABLE _IO('c', 102)

enum kfuz_mode {
	HWIOFUZZ_MODE_DISABLED = 0,
	HWIOFUZZ_MODE_TRACE = 1,
};

/*
 * kfuz descriptor (one per opened debugfs file).
 * State transitions of the descriptor:
 *  - initial state after open()
 *  - then there must be a single ioctl(HWIOFUZZ_INIT_TRACE) call
 *  - then, mmap() call (several calls are allowed but not useful)
 *  - then, repeated enable/disable for a task (only one task a time allowed)
 */
struct kfuz {
	/*
	 * Reference counter. We keep one for:
	 *  - opened file descriptor
	 *  - task with enabled kfuz (we can't unwire it from another task)
	 */
	atomic_t refcount;
	/* The lock protects mode, size, area and t. */
	spinlock_t lock;
	enum kfuz_mode mode;
	/* Size of arena (in long's for HWIOFUZZ_MODE_TRACE). */
	unsigned size;
	/* Mutation buffer shared with user space. */
	void *area;
	/* Task from which we get mutation, or NULL. */
	struct task_struct *t;

	bool enabled;
	bool inited;
	bool consumed;
	long highwatermark;
};

static struct kfuz *hwiofuzz;
static void *kfuz_area;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_CTX_STATIC

static u8 kfuz_mask[PAGE_SIZE];

#elif HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC

struct kfuz_access {
	struct list_head list;
	unsigned long addr;
	size_t len;
	int kfuz_area_offset;
};

// support only up to 1024 traps to cacheable memory in one interrupt
#define HWIOFUZZ_ACCESS_POOL_SIZE 1024
static struct kfuz_access kfuz_access_pool[HWIOFUZZ_ACCESS_POOL_SIZE];
static atomic_t kfuz_access_pool_cnt;

static LIST_HEAD(cacheable_writes);
static LIST_HEAD(cacheable_reads);

#endif

#define FF(_b) (0xff << ((_b) << 3))

static u32 count_bytes(u8 *mem, u32 mem_size)
{
	u32 *ptr = (u32 *)mem;
	u32 i = (mem_size >> 2);
	u32 ret = 0;

	while (i--) {
		u32 v = *(ptr++);

		if (!v)
			continue;
		if (v & FF(0))
			ret++;
		if (v & FF(1))
			ret++;
		if (v & FF(2))
			ret++;
		if (v & FF(3))
			ret++;
	}
	return ret;
}

bool kfuz_hwiotrace_init(void)
{
	struct kfuz *kfuz = hwiofuzz;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC
	struct kfuz_access *access;
	struct kfuz_access *tmp;
#endif

	if (!kfuz || !kfuz->enabled || kfuz->inited || kfuz->consumed)
		return false;

	if (!kfuz_area)
		return false;

	pr_info("kfuz_hwiotrace_init kfuz_area=%p kfuz->size=%u count=%u\n",
		kfuz_area, kfuz->size, count_bytes(kfuz_area, kfuz->size));

	kfuz->inited = true;
	kfuz->highwatermark = 0;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_CTX_STATIC

	memset(kfuz_mask, 0x0, kfuz->size);

#elif HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC

	atomic_set(&kfuz_access_pool_cnt, 0);

	list_for_each_entry_safe (access, tmp, &cacheable_writes, list) {
		list_del(&access->list);
	}

	list_for_each_entry_safe (access, tmp, &cacheable_reads, list) {
		list_del(&access->list);
	}

#endif

	return true;
}

bool kfuz_hwiotrace_exit(void)
{
	struct kfuz *kfuz = hwiofuzz;

	if (!kfuz)
		return false;

	if (!kfuz_area)
		return false;

	if (!kfuz->inited)
		return false;

	pr_info("kfuz_hwiotrace_exit kfuz_area=%p kfuz->size=%u kfuz->highwatermark=0x%lx count=%u\n",
		kfuz_area, kfuz->size, kfuz->highwatermark,
		count_bytes(kfuz_area, kfuz->size));

	kfuz->inited = false;

	if (kfuz->highwatermark > 0) {
		kfuz->consumed = true;
		memset(kfuz_area, 0xab, kfuz->highwatermark);
	}

	return true;
}

bool kfuz_hwiotrace_consume(void *dest, unsigned long base, int offset,
			    unsigned long len, bool cacheable)
{
	struct kfuz *kfuz = hwiofuzz;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_CTX_STATIC

	unsigned i;

	if (offset < 0 || offset + len > PAGE_SIZE)
		return false;

#elif HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC

	bool found = false;

#endif

	if (!dest)
		return false;

	if (!kfuz || !kfuz->inited || kfuz->consumed)
		return false;

	if (!kfuz_area)
		return false;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_CTX_STATIC

	/*
	 * highwatermark indicates the last offset to which the fuzzer buffer
	 * has been consumed
	 */

	if (kfuz->highwatermark < offset + len)
		kfuz->highwatermark = offset + len;

	// TODO: is this too strict?
	// if any byte of value is masked, do not fuzz
	for (i = 0; i < len; i++) {
		if (kfuz_mask[offset + i]) {
			pr_info("kfuz_hwiotrace_consume masked at %d + %u\n",
				offset, i);
			return false;
		}
	}

	memcpy(dest, kfuz_area + offset, len);

#elif HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC

	/*
	 * highwatermark indicates next offset of the fuzzer buffer to consume
	 */

	if (kfuz->highwatermark + len > PAGE_SIZE)
		return false;

	if (cacheable) {
		struct kfuz_access *access;
		struct kfuz_access *tmp;
		unsigned long addr = base + offset;

		/*
		 * we do not want to fuzz cacheable memory overwritten by driver
		 */
		list_for_each_entry (access, &cacheable_writes, list) {
			// TODO: may need to be more precise
			if ((access->addr <= addr &&
			     addr < access->addr + access->len) ||
			    (addr <= access->addr &&
			     access->addr < addr + len)) {
				pr_info("value overwritten by the driver\n");
				return false;
			}
		}

		/*
		 * we do not want to provide different values to multi-reads
		 * of cacheable memory
		 */
		list_for_each_entry_safe (access, tmp, &cacheable_reads, list) {
			if (access->addr <= addr &&
			    addr + len <= access->addr + access->len) {
				memcpy(dest,
				       kfuz_area + access->kfuz_area_offset,
				       len);
				pr_info("multi-reads of cacheable memory\n");
				return true;
			}

			// handle partial overlap cases by overwriting fuzzer buffer
			if ((addr <= access->addr &&
			     access->addr < addr + len) ||
			    (access->addr <= addr &&
			     addr < access->addr + access->len)) {
				int overlap_start = 0;
				int overlap_end = len;
				int kfuz_area_offset = 0;

				if (addr < access->addr) {
					overlap_start = access->addr - addr;
				}

				if (access->addr + access->len < addr + len) {
					overlap_end = access->addr +
						      access->len - addr;
				}

				if (access->addr < addr) {
					kfuz_area_offset = addr - access->addr;
				}

				pr_info("overlapping multi-reads of cacheable memory at 0x%x (+0x%x)\n",
					overlap_start,
					overlap_end - overlap_start);

				memcpy(kfuz_area + kfuz->highwatermark +
					       overlap_start /* dest */,
				       kfuz_area + access->kfuz_area_offset +
					       kfuz_area_offset /* src */,
				       overlap_end - overlap_start /* sz */);
			}

			// optimization
			if (addr <= access->addr &&
			    access->addr + len <= addr + len) {
				pr_info("(optimization) updating previous cacheable read\n");
				access->addr = addr;
				access->len = len;
				access->kfuz_area_offset = kfuz->highwatermark;
				found = true;
			}
		}
	}

	memcpy(dest, kfuz_area + kfuz->highwatermark, len);

	// add new entry for future cacheable reads
	if (cacheable && !found) {
		struct kfuz_access *new_access;
		int idx = atomic_inc_return(&kfuz_access_pool_cnt);
		if (idx > HWIOFUZZ_ACCESS_POOL_SIZE) {
			pr_warn("kfuz_hwiotrace_consume pool alloc failed\n");
			return false;
		}
		new_access = &kfuz_access_pool[idx - 1];
		new_access->addr = base + offset;
		new_access->len = len;
		new_access->kfuz_area_offset = kfuz->highwatermark;

		list_add(&new_access->list, &cacheable_reads);
	}

	kfuz->highwatermark += len;
	pr_info("new highwatermark=0x%lx\n", kfuz->highwatermark);

#endif

	return true;
}

bool kfuz_hwiotrace_mask(unsigned long base, int offset, unsigned long len)
{
	struct kfuz *kfuz = hwiofuzz;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC
	struct kfuz_access *access;
	bool found = false;
#endif

	if (!kfuz || !kfuz->inited || kfuz->consumed)
		return false;

#if HWIOFUZZ_MAPPING == HWIOFUZZ_PER_CTX_STATIC

	if (offset < 0 || offset + len > PAGE_SIZE)
		return false;

	// TODO: should we update high-water mark?

	memset(kfuz_mask + offset, 0xff, len);

#elif HWIOFUZZ_MAPPING == HWIOFUZZ_PER_IRQ_DYNAMIC

	list_for_each_entry (access, &cacheable_writes, list) {
		unsigned long addr = base + offset;

		if (addr <= access->addr && access->addr <= addr + len) {
			access->addr = addr;
			if (access->addr + access->len < addr + len) {
				access->len = addr + len - access->addr;
			}
			found = true;
			break;
		}

		if (access->addr <= addr &&
		    addr <= access->addr + access->len) {
			if (access->addr + access->len < addr + len) {
				access->len = addr + len - access->addr;
			}
			found = true;
			break;
		}
	}

	if (!found) {
		struct kfuz_access *new_access;
		int idx = atomic_inc_return(&kfuz_access_pool_cnt);
		if (idx > HWIOFUZZ_ACCESS_POOL_SIZE) {
			pr_warn("kfuz_hwiotrace_consume pool alloc failed\n");
			return false;
		}
		new_access = &kfuz_access_pool[idx - 1];
		new_access->addr = base + offset;
		new_access->len = len;

		list_add(&new_access->list, &cacheable_writes);
	}

#endif

	return true;
}

static void kfuz_get(struct kfuz *kfuz)
{
	atomic_inc(&kfuz->refcount);
}

static void kfuz_put(struct kfuz *kfuz)
{
	if (atomic_dec_and_test(&kfuz->refcount)) {
		hwiofuzz = NULL;
		kfuz_area = NULL;
		vfree(kfuz->area);
		kfree(kfuz);
	}
}

static int kfuz_mmap(struct file *filep, struct vm_area_struct *vma)
{
	int res = 0;
	void *area;
	struct kfuz *kfuz = vma->vm_file->private_data;
	unsigned long size, off;
	struct page *page;

	area = vmalloc_user(vma->vm_end - vma->vm_start);
	if (!area)
		return -ENOMEM;

	spin_lock(&kfuz->lock);
	size = kfuz->size;

	if (kfuz->mode == HWIOFUZZ_MODE_DISABLED || vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start != size) {
		res = -EINVAL;
		goto exit;
	}
	if (!kfuz->area) {
		kfuz->area = area;
		vma->vm_flags |= VM_DONTEXPAND;
		spin_unlock(&kfuz->lock);
		for (off = 0; off < size; off += PAGE_SIZE) {
			page = vmalloc_to_page(kfuz->area + off);
			if (vm_insert_page(vma, vma->vm_start + off, page))
				WARN_ONCE(1, "vm_insert_page() failed");
		}
		return 0;
	}
exit:
	spin_unlock(&kfuz->lock);
	vfree(area);
	return res;
}

static int kfuz_open(struct inode *inode, struct file *filep)
{
	struct kfuz *kfuz;

	kfuz = kzalloc(sizeof(*kfuz), GFP_KERNEL);
	if (!kfuz)
		return -ENOMEM;
	atomic_set(&kfuz->refcount, 1);
	spin_lock_init(&kfuz->lock);
	filep->private_data = kfuz;
	return nonseekable_open(inode, filep);
}

static int kfuz_close(struct inode *inode, struct file *filep)
{
	kfuz_put(filep->private_data);
	return 0;
}

static long kfuz_ioctl_locked(struct kfuz *kfuz, unsigned int cmd,
			      unsigned long arg)
{
	struct task_struct *t;
	unsigned long size, unused;

	switch (cmd) {
	case HWIOFUZZ_INIT:
		if (kfuz->mode != HWIOFUZZ_MODE_DISABLED)
			return -EBUSY;
		size = arg;
		if (size < 1 || size > PAGE_SIZE)
			return -EINVAL;
		kfuz->size = size;
		kfuz->mode = HWIOFUZZ_MODE_TRACE;
		return 0;
	case HWIOFUZZ_CONSUME_ENABLE:
		unused = arg;
		if (unused != 0 || kfuz->mode == HWIOFUZZ_MODE_DISABLED ||
		    kfuz->area == NULL)
			return -EINVAL;
		pr_info("consumption enabled\n");
		t = current;
		kfuz->t = t;
		kfuz->enabled = true;
		kfuz->inited = false;
		kfuz->consumed = false;
		kfuz_get(kfuz);
		hwiofuzz = kfuz;
		kfuz_area = kfuz->area;
		return 0;
	case HWIOFUZZ_CONSUME_CHECK:
		pr_info("highwatermark=0x%lx\n", kfuz->highwatermark);
		return kfuz->consumed ? kfuz->highwatermark : -EINVAL;
	case HWIOFUZZ_CONSUME_DISABLE:
		pr_info("consumption disabled\n");
		t = current;
		kfuz->t = NULL;
		kfuz->enabled = false;
		hwiofuzz = NULL;
		kfuz_area = NULL;
		kfuz_put(kfuz);
		return 0;
	default:
		return -ENOTTY;
	}
}

static long kfuz_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kfuz *kfuz;
	int res;

	kfuz = filep->private_data;
	spin_lock(&kfuz->lock);
	res = kfuz_ioctl_locked(kfuz, cmd, arg);
	spin_unlock(&kfuz->lock);
	return res;
}

static const struct file_operations kfuz_fops = {
	.open = kfuz_open,
	.unlocked_ioctl = kfuz_ioctl,
	.mmap = kfuz_mmap,
	.release = kfuz_close,
};

static int __init hwiofuzz_init(void)
{
	if (!debugfs_create_file("kfuz", 0600, NULL, NULL, &kfuz_fops)) {
		pr_err("failed to create kfuz in debugfs\n");
		return -ENOMEM;
	}
	return 0;
}

device_initcall(hwiofuzz_init);
