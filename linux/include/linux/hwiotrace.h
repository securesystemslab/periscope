#ifndef _LINUX_HWIOTRACE_H
#define _LINUX_HWIOTRACE_H

#include <linux/device.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/decode.h>

#define MAX_STALLED_PROBE_DRV_NAME 64

struct khwio_probe;
struct pt_regs;

typedef void (*khwio_pre_handler_t)(struct khwio_probe *, struct pt_regs *,
				    unsigned long addr, struct Insn *);
typedef void (*khwio_post_handler_t)(struct khwio_probe *,
				     unsigned long condition, struct pt_regs *,
				     struct Insn *);

struct khwio_probe {
	/* khwio internal list: */
	struct list_head list;
	/* start location of the probe point: */
	unsigned long addr;
	/* probe call context */
	unsigned long ctx;
	/* length of the probe region: */
	unsigned long len;
	/* Called before addr is executed: */
	khwio_pre_handler_t pre_handler;
	/* Called after addr is executed: */
	khwio_post_handler_t post_handler;
	/* how many times has this memory been read */
	size_t n_read;
	/* how many times has this memory been written */
	size_t n_write;
	/* non-cacheable memory allows for temporal modification of buffer */
	bool cacheable;
	void *private;
};

extern unsigned int khwio_count;

extern int register_khwio_probe(struct khwio_probe *p);
extern void unregister_khwio_probe(struct khwio_probe *p);
extern int khwio_init(void);
extern void khwio_cleanup(void);

#ifdef CONFIG_HWIOTRACE
/* khwio is active by some khwio_probes? */
static inline int is_khwio_active(void)
{
	return khwio_count;
}

/* Called from page fault handler. */
int khwio_handler(struct pt_regs *regs, unsigned long addr);
int khwio_breakpoint_handler(struct pt_regs *regs, unsigned int esr);
int khwio_single_step_handler(struct pt_regs *regs, unsigned int esr);

/* Called from ioremap.c */
extern void hwiotrace_ioremap(resource_size_t offset, unsigned long size,
			      void __iomem *addr);
extern void hwiotrace_iounmap(volatile void __iomem *addr);

/* Called from dma-mapping.c */
extern void hwiotrace_sync_single_for_cpu(void *addr, unsigned long size);
extern void hwiotrace_sync_single_for_device(void *addr);

int hwiotrace_activate_probe(void *addr, unsigned long size, unsigned long ctx,
			     bool cacheable);

extern void hwiotrace_free(void *addr);

/* For anyone to insert markers. Remember trailing newline. */
extern __printf(1, 2) int hwiotrace_printk(const char *fmt, ...);
#else /* !CONFIG_HWIOTRACE: */
static inline int is_khwio_active(void)
{
	return 0;
}

static inline int khwio_handler(struct pt_regs *regs, unsigned long addr)
{
	return 0;
}

static inline void hwiotrace_ioremap(resource_size_t offset, unsigned long size,
				     void __iomem *addr)
{
}

static inline void hwiotrace_iounmap(volatile void __iomem *addr)
{
}

static inline __printf(1, 2) int hwiotrace_printk(const char *fmt, ...)
{
	return 0;
}
#endif /* CONFIG_HWIOTRACE */

enum hw_io_opcode {
	HWIO_READ = 0x1, /* struct hwiotrace_rw */
	HWIO_WRITE = 0x2, /* struct hwiotrace_rw */
	HWIO_PROBE = 0x3, /* struct hwiotrace_map */
	HWIO_UNPROBE = 0x4, /* struct hwiotrace_map */
	HWIO_TASK_START = 0x5, /* struct hwiotrace_task */
	HWIO_TASK_END = 0x6, /* struct hwiotrace_task */
	HWIO_UNKNOWN_OP = 0x7, /* struct hwiotrace_rw */
};

struct hwiotrace_rw {
	resource_size_t phys; /* PCI address of register */
	unsigned long virt;
	unsigned long pc; /* optional program counter */
	int map_id;
	unsigned char width; /* size of register access in bytes */
	unsigned long value;
	unsigned char opcode; /* one of HWIO_{READ,WRITE,UNKNOWN_OP} */
};

struct hwiotrace_map {
	resource_size_t phys; /* base address in PCI space */
	unsigned long virt; /* base virtual address */
	unsigned long pc;
	int map_id;
	unsigned long len; /* mapping size */
	unsigned char opcode; /* HWIO_PROBE or HWIO_UNPROBE */
};

struct hwiotrace_task {
	int task_id;
	unsigned char opcode; /* HWIO_TASK_START or HWIO_TASK_END */
};

struct dma_sync_trace {
	struct list_head list;
	struct khwio_probe probe;
	resource_size_t phys;
	unsigned long id;
};

/* in kernel/trace/trace_hwiotrace.c */
struct list_head *sync_trace_list_get(unsigned long *flags);
void sync_trace_list_put(unsigned long flags);
extern bool is_hwiotrace_enabled(void);
extern void enable_hwiotrace(void);
extern void activate_hwiotrace(const char *, int, int, int);
extern void disable_hwiotrace(void);
extern void hwiotrace_task_start(void);
extern void hwiotrace_task_end(void);
extern void hwio_trace_rw(struct hwiotrace_rw *rw);
extern void hwio_trace_mapping(struct hwiotrace_map *map);
extern void hwio_trace_task(struct hwiotrace_task *task);
extern __printf(1, 0) int hwio_trace_printk(const char *fmt, va_list args);
extern unsigned long get_hwio_context(void);

enum PROBE_TYPE { DMA_STREAM, DMA_CONSIST, MMIO };
extern const char *probe_type_names[];

struct hwiotrace_probe {
	/* khwio internal list: */
	struct list_head list;
	/* the name of the driver for which this probe is registered */
	char drv_name[MAX_STALLED_PROBE_DRV_NAME];
	/* probe call context */
	unsigned long ctx;
	/* unique probe id */
	size_t id;
	/* is the buffer currently mapped */
	size_t current_map_id;
	/* active mappings for this probe point */
	struct list_head mappings;
	/* activate future mappings for this probe point */
	bool tracing;
	/* the last mapped size for this context */
	void *last_va;
	/* the last mapped size for this context */
	size_t last_length;
	/* type of the probe point */
	enum PROBE_TYPE type;
	// TODO: @dokyung maybe we don't need this anymore?
	// I'd rather keep this for now to optimize for heavy-traffic DMA
	// streaming buffers. The problem is that the deallocation is not
	// really trackable, so I cannot reasonably get memory and CPU
	// consumption under my control
	/* heavy-traffic transient buffers where only a single mapping can
	   be active at any point. So we do not track active mappings of
	   probes of this type */
	bool transient;
};

struct hwiotrace_mapping {
	/* probe point list: */
	struct list_head list_pp;

	/* global list: */
	struct list_head list_glob;

	/* length of the mapping */
	unsigned long size;

	/* virtual address of the mapping */
	void *va;

	/* unique mapping id */
	size_t map_id;

	/* ptr to probe point for this mapping */
	struct hwiotrace_probe *pp;

	/* currently tracing this mapping */
	bool tracing;
};

struct list_head *hwiotrace_mappings_get(unsigned long *flags);
void hwiotrace_mappings_put(unsigned long flags);
struct list_head *hwiotrace_probes_get(unsigned long *flags);
void hwiotrace_probes_put(unsigned long flags);
int unregister_hwiotrace_probe(const char *drv_name, void *pa);
int register_hwiotrace_probe(const char *drv_name, void *pa, size_t size,
			     enum PROBE_TYPE type);
int __register_hwiotrace_probe(const char *drv_name, void *pa, size_t size,
			       bool transient, enum PROBE_TYPE);
int unregister_hwiotrace_probe(const char *drv_name, void *pa);
int activate_hwiotrace_probe(const char *drv_name, unsigned long ctx,
			     size_t id);
int deactivate_hwiotrace_probe(const char *drv_name, unsigned long ctx,
			       size_t id);
int stop_all_hwiotrace_probes(void);
int remove_all_hwiotrace_probes(void);
int hwio_get_some_name(char *nameout);

#endif /* _LINUX_HWIOTRACE_H */
