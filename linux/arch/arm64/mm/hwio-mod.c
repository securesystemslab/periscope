/*
 * Extended mmio-mod.c for arm64 and DMA support
 */

#define pr_fmt(fmt) "hwiotrace: " fmt

#define DEBUG 1

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kallsyms.h>
#include <asm/pgtable.h>
#include <asm/stacktrace.h>
#include <linux/hwiotrace.h>
#include <linux/hwiofuzz.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/kcov.h>

struct trap_reason {
	unsigned long addr;
	unsigned long ip;
	//enum reason_type type;
	int active_traces;
};

struct remap_trace {
	struct list_head list;
	struct khwio_probe probe;
	resource_size_t phys;
	unsigned long id;
};

/* Accessed per-cpu. */
static DEFINE_PER_CPU(struct trap_reason, pf_reason);
static DEFINE_PER_CPU(struct hwiotrace_rw, cpu_trace);

static DEFINE_MUTEX(hwiotrace_mutex);
static DEFINE_SPINLOCK(trace_lock);
static atomic_t hwiotrace_enabled;
static LIST_HEAD(trace_list); /* struct remap_trace */

#define DMA_SYNC_TRACE_PROBE 1

static DEFINE_SPINLOCK(sync_trace_lock);
static LIST_HEAD(sync_trace_list); /* struct sync_trace */

struct list_head *sync_trace_list_get(unsigned long *flags)
{
	spin_lock_irqsave(&sync_trace_lock, *flags);
	return &sync_trace_list;
}

void sync_trace_list_put(unsigned long flags)
{
	spin_unlock_irqrestore(&sync_trace_lock, flags);
}

/*
 * Locking in this file:
 * - mmiotrace_mutex enforces enable/disable_mmiotrace() critical sections.
 * - mmiotrace_enabled may be modified only when holding mmiotrace_mutex
 *   and trace_lock.
 * - Routines depending on is_enabled() must take trace_lock.
 * - trace_list users must hold trace_lock.
 * - is_enabled() guarantees that mmio_trace_{rw,mapping} are allowed.
 * - pre/post callbacks assume the effect of is_enabled() being true.
 */

/* module parameters */
static unsigned long filter_offset;
static bool nohwiotrace;
static const char *dma_dev;

enum dma_flags {
	HWIOTRACE_DMA_SYNC = 0x1,
	HWIOTRACE_DMA_MAP = 0x2,
};
static int dma_flag;

module_param(filter_offset, ulong, 0);
module_param(nohwiotrace, bool, 0);

MODULE_PARM_DESC(filter_offset, "Start address of traced mappings.");
MODULE_PARM_DESC(nohwiotrace, "Disable actual HWIO tracing.");

static bool is_enabled(void)
{
	return atomic_read(&hwiotrace_enabled);
}

#define REGISTER_HWIOTRACE_PROBE 1
#define VERBOSE_LOGGING 0

// TODO: not sure if this gives consistent addresses across reboots
#define HWIOTRACE_PC_MASK (((unsigned long)1 << 20) - 1)

const char *probe_type_names[] = { "DMA_STREAM", "DMA_CONSIST", "MMIO" };
static DEFINE_SPINLOCK(probes_lock);
static LIST_HEAD(probes);
static LIST_HEAD(active_mappings);
static atomic_t probe_id;

struct list_head *hwiotrace_mappings_get(unsigned long *flags)
{
	spin_lock_irqsave(&probes_lock, *flags);
	return &active_mappings;
}

void hwiotrace_mappings_put(unsigned long flags)
{
	spin_unlock_irqrestore(&probes_lock, flags);
}

struct list_head *hwiotrace_probes_get(unsigned long *flags)
{
	spin_lock_irqsave(&probes_lock, *flags);
	return &probes;
}

void hwiotrace_probes_put(unsigned long flags)
{
	spin_unlock_irqrestore(&probes_lock, flags);
}

unsigned long get_hwio_context(void)
{
	static unsigned long __do_softirq_size = 0;

	unsigned long xor = 0;

	struct stackframe frame;
	frame.fp = (unsigned long)__builtin_frame_address(0);
	frame.sp = current_stack_pointer;
	frame.pc = (unsigned long)get_hwio_context;

	while (1) {
		int ret;

		ret = unwind_frame(current, &frame);
		if (ret < 0)
			break;

		if (__do_softirq_size == 0) {
			unsigned long offset;
			kallsyms_lookup_size_offset((unsigned long)__do_softirq,
						    &__do_softirq_size,
						    &offset);
		}

		// TODO: more blacklisting
		if (frame.pc >= (unsigned long)__do_softirq &&
		    frame.pc < (unsigned long)__do_softirq + __do_softirq_size)
			break;

		xor ^= frame.pc &HWIOTRACE_PC_MASK;
	}
	return xor;
}

// must hold
// spin_lock_irqsave(&probes_lock, flags);
static struct hwiotrace_probe *get_probe_by_ctx(unsigned long ctx)
{
	struct hwiotrace_probe *pp;
	struct hwiotrace_probe *ret_pp = NULL;

	list_for_each_entry (pp, &probes, list) {
		if (pp->ctx == ctx) {
			ret_pp = pp;
			break;
		}
	}
	return ret_pp;
}

// must hold
// spin_lock_irqsave(&probes_lock, flags);
static struct hwiotrace_mapping *
find_probe_mapping_by_va(void *va, struct hwiotrace_probe *pp)
{
	struct hwiotrace_mapping *am;
	struct hwiotrace_mapping *ret_am = NULL;
	list_for_each_entry (am, &pp->mappings, list_pp) {
		if (am->va == va) {
			ret_am = am;
			break;
		}
	}
	return ret_am;
}

// must hold
// spin_lock_irqsave(&probes_lock, flags);
static struct hwiotrace_mapping *new_mapping(void *vaddr, size_t size,
					     struct hwiotrace_probe *pp)
{
	struct hwiotrace_mapping *am;
	am = find_probe_mapping_by_va(vaddr, pp);
	if (am == NULL) {
		am = kmalloc(sizeof(struct hwiotrace_mapping), GFP_ATOMIC);
		if (am == NULL) {
			pr_err("Error allocating hwiotrace_mapping @ %p\n",
			       vaddr);
			return NULL;
		}
		am->size = size;
		am->va = vaddr;
		am->map_id = pp->current_map_id++;
		am->pp = pp;
		am->tracing = false;

		// add active mapping to probe point
		list_add(&am->list_pp, &pp->mappings);

		// add active mapping to global list
		list_add(&am->list_glob, &active_mappings);
	}

	return am;
}

// must hold
// spin_lock_irqsave(&probes_lock, flags);
static int remove_active_mapping_from_probe(struct hwiotrace_probe *pp,
					    size_t map_id)
{
	struct hwiotrace_mapping *am;
	struct hwiotrace_mapping *tmp;
	list_for_each_entry_safe (am, tmp, &pp->mappings, list_pp) {
		if (am->map_id == map_id) {
			list_del(&am->list_pp);
			return 0;
		}
	}
	return -EFAULT;
}

int unregister_hwiotrace_probe(const char *drv_name, void *addr)
{
	int ret = -EFAULT;
	unsigned long flags;

	struct hwiotrace_mapping *am;
	struct hwiotrace_mapping *tmp;

#if VERBOSE_LOGGING
	pr_info("Unregistering consistent probes @ %p\n", addr);
#endif
	if (!is_hwiotrace_enabled()) {
		return -EFAULT;
	}

	if (addr == NULL) {
		return -EFAULT;
	}

	if (drv_name != NULL && strcmp(drv_name, "18800000.qcom,icnss") != 0) {
		return -EFAULT;
	}

	spin_lock_irqsave(&probes_lock, flags);

	// TODO: can be optimized; querying all active mappings might hold
	// CPU for long time, when this function can be called with a
	// constrained time budget e.g., in interrupt context.
	list_for_each_entry_safe (am, tmp, &active_mappings, list_glob) {
		if (addr >= am->va && addr < am->va + am->size) {
			// remove mapping from parent
			if (remove_active_mapping_from_probe(am->pp,
							     am->map_id) != 0) {
				pr_err("Error failed to remove mapping %zu from parent list\n",
				       am->map_id);
			} else {
				// if this probe is activated, unregister probe for this mapping
				if (am->pp->tracing) {
					if (am->tracing) {
#if REGISTER_HWIOTRACE_PROBE
						hwiotrace_sync_single_for_device(
							(void *)am->va);
#endif
						am->tracing = false;
					}
				}

				list_del(&am->list_glob);
				kfree(am);
				// there should not be two mappings with the same va
				break;
			}
		}
	}

	spin_unlock_irqrestore(&probes_lock, flags);

	return ret;
}

int register_hwiotrace_probe(const char *drv_name, void *vaddr, size_t size,
			     enum PROBE_TYPE type)
{
	return __register_hwiotrace_probe(drv_name, vaddr, size, false, type);
}

int __register_hwiotrace_probe(const char *drv_name, void *vaddr, size_t size,
			       bool transient, enum PROBE_TYPE type)
{
	int ret = 0;
	unsigned long flags;
	unsigned long ctx;
	struct hwiotrace_probe *pp;
	struct hwiotrace_mapping *am;

	if (drv_name == NULL ||
	    (type == DMA_STREAM &&
	     strcmp(drv_name, "18800000.qcom,icnss") != 0)) {
		return -EFAULT;
	}

	if (vaddr == NULL) {
		return -EFAULT;
	}

	if (transient && !is_hwiotrace_enabled()) {
		// Transient buffers can wait; likely be reallocated after hwiotrace is enabled
		return -EFAULT;
	}

	ctx = get_hwio_context();

	spin_lock_irqsave(&probes_lock, flags);

	// get already existing probe for context if any
	// TODO maybe add name
	pp = get_probe_by_ctx(ctx);

#if VERBOSE_LOGGING
	pr_info("Registering stalled probe for %s @ %lx, %p (+%lx)\n", drv_name,
		ctx, vaddr, size);
#endif

	// create new probe if none present for ctx
	if (pp == NULL) {
		pp = kmalloc(sizeof(struct hwiotrace_probe), GFP_ATOMIC);
		if (pp == NULL) {
			pr_err("Error allocating hwiotrace_probe for driver %s\n",
			       drv_name);
			ret = -EFAULT;
			goto out;
		}

		// generate new unique probe id
		atomic_inc(&probe_id);

		// init probe data
		strncpy(pp->drv_name, drv_name, MAX_STALLED_PROBE_DRV_NAME);
		pp->ctx = ctx;
		pp->id = atomic_read(&probe_id);
		pp->current_map_id = 1;
		pp->tracing = false;
		pp->type = type;
		pp->last_va = NULL;
		pp->last_length = 0;
		INIT_LIST_HEAD(&pp->mappings);
		// add new probe point to global list
		list_add(&pp->list, &probes);

		//pr_info("Registered new stalled probe for %s @ %lx, %lx (+%lx)\n",
		//      drv_name, pp->ctx, pp->va, pp->size);
	}

	// unregister the existing active mapping associated with the context;
	// sometimes deallocation of a buffer is not really hookable without
	// uselessly calling hooking function a lot of times
	if (!transient) {
		// generate new active mapping and add it to probe point
		am = new_mapping(vaddr, size, pp);
		if (am == NULL) {
			pr_err("Error allocating hwiotrace_mapping for driver %s\n",
			       drv_name);
			ret = -EFAULT;
			goto out;
		}
	}

	// if this probe is activated, register probe for this mapping
	if (pp->tracing) {
#if REGISTER_HWIOTRACE_PROBE
		bool cacheable = false;
		if (type == DMA_STREAM) {
			cacheable = true;
		}

		if (transient && pp->last_va != NULL) {
			hwiotrace_sync_single_for_device(pp->last_va);
		}

		if (hwiotrace_activate_probe((void *)vaddr, size, pp->ctx,
					     cacheable) == 0) {
			if (am && !am->tracing) {
				am->tracing = true;
			}
		}
#endif
	}

	pp->last_va = vaddr;
	pp->last_length = size;

out:
	spin_unlock_irqrestore(&probes_lock, flags);

	return ret;
}

int activate_hwiotrace_probe(const char *drv_name, unsigned long ctx, size_t id)
{
	unsigned long flags;
	struct hwiotrace_probe *pp;
	struct hwiotrace_mapping *am;

	pr_info("activate probe name: %s, ctx: 0x%lx, id: %ld\n",
		drv_name ? drv_name : "(null)", ctx, id);

	spin_lock_irqsave(&probes_lock, flags);
	list_for_each_entry (pp, &probes, list) {
		if (((drv_name == NULL) ||
		     strncmp(pp->drv_name, drv_name,
			     MAX_STALLED_PROBE_DRV_NAME) == 0) &&
		    ((ctx == 0) || pp->ctx == ctx) &&
		    ((id == 0) || pp->id == id)) {
			// set flag to activate furute mappings
			pp->tracing = true;
			// if we do this we might hit previously freed and reallocated mappings,
			// which are not used for dma anymore (for streaming dma)
			// so only do that for consistent dma mappings
			// and maybe mmio mappings, dependent on how they are used?
			if (pp->type == DMA_CONSIST) {
				// start tracing on all current mappings
				list_for_each_entry (am, &pp->mappings,
						     list_pp) {
					if (!am->tracing) {
#if REGISTER_HWIOTRACE_PROBE
						if (hwiotrace_activate_probe(
							    (void *)am->va,
							    am->size, pp->ctx,
							    false) == 0)
							am->tracing = true;
#endif
					}
				}
			}
		}
	}
	spin_unlock_irqrestore(&probes_lock, flags);

	return 0;
}

int deactivate_hwiotrace_probe(const char *drv_name, unsigned long ctx,
			       size_t id)
{
	unsigned long flags;
	struct hwiotrace_probe *pp;
	struct hwiotrace_mapping *am;

	//pr_info("deactivate probe name: %s, ctx: 0x%lx, id: %ld, addr: 0x%lx\n",
	//      drv_name ? drv_name : "(null)", ctx, id, addr);

	spin_lock_irqsave(&probes_lock, flags);
	list_for_each_entry (pp, &probes, list) {
		if (((drv_name == NULL) ||
		     strncmp(pp->drv_name, drv_name,
			     MAX_STALLED_PROBE_DRV_NAME) == 0) &&
		    ((ctx == 0) || pp->ctx == ctx) &&
		    ((id == 0) || pp->id == id)) {
			// set flag to deactivate furute mappings
			pp->tracing = false;
			// if we do this we might hit previously freed and reallocated mappings,
			// which are not used for dma anymore (for streaming dma)
			// so only do that for consistent dma mappings
			// and maybe mmio mappings, dependent on how they are used?
			if (pp->type == DMA_CONSIST) {
				// start tracing on all current mappings
				list_for_each_entry (am, &pp->mappings,
						     list_pp) {
					if (!am->tracing) {
#if REGISTER_HWIOTRACE_PROBE
						hwiotrace_sync_single_for_device(
							(void *)am->va);
#endif
						am->tracing = false;
					}
				}
			}
		}
	}
	spin_unlock_irqrestore(&probes_lock, flags);
	return 0;
}

int stop_all_hwiotrace_probes(void)
{
	return deactivate_hwiotrace_probe(NULL, 0, 0);
	return 0;
}

int remove_all_hwiotrace_probes(void)
{
	// unsigned long flags;
	// //pr_info("Unregistering consistent probes\n");

	// struct hwiotrace_probe *sp;
	// struct hwiotrace_probe *tmp;

	// spin_lock_irqsave(&probes_lock, flags);
	// list_for_each_entry_safe(sp, tmp, &probes, list) {
	//    if(sp->active) {
	//       hwiotrace_sync_single_for_device((void*)sp->va);
	//    }
	//    list_del(&sp->list);
	//    kfree(sp);
	// }
	// spin_unlock_irqrestore(&probes_lock, flags);

	return 0;
}

int hwio_get_some_name(char *nameout)
{
	struct stackframe frame;
	unsigned long symbolsize;
	unsigned long offset;
	register unsigned long current_sp asm("sp");
	char namebuf[KSYM_SYMBOL_LEN];
	char *modname;
	size_t nlen;
	size_t i;

	frame.fp = (unsigned long)__builtin_frame_address(0);
	frame.sp = current_sp;
	frame.pc = (unsigned long)hwio_get_some_name;

	for (i = 0; i < 4; ++i) {
		if (unwind_frame(current, &frame) < 0)
			return -EFAULT;

		if (i < 2)
			continue;

		if (kallsyms_lookup(frame.pc, &symbolsize, &offset, &modname,
				    namebuf) == NULL)
			return -EFAULT;

		strncpy(nameout, namebuf, KSYM_SYMBOL_LEN);
		nlen = strlen(namebuf);
		nameout += nlen;
		*nameout = '.';
		nameout++;
	}
	return 0;
}

/*
 * For some reason the pre/post pairs have been called in an
 * unmatched order. Report and die.
 */
static void die_khwio_nesting_error(struct pt_regs *regs, unsigned long addr)
{
	const struct trap_reason *my_reason = &get_cpu_var(pf_reason);
	pr_emerg(
		"unexpected fault for address: 0x%08lx, last fault for address: 0x%08lx\n",
		addr, my_reason->addr);
	print_symbol(KERN_EMERG "faulting pc is at %s\n",
		     instruction_pointer(regs));
	put_cpu_var(pf_reason);
	BUG();
}

static void pre(struct khwio_probe *p, struct pt_regs *regs, unsigned long addr,
		struct Insn *instr)
{
	struct trap_reason *my_reason = &get_cpu_var(pf_reason);
	struct hwiotrace_rw *my_trace = &get_cpu_var(cpu_trace);
	const unsigned long instptr = instruction_pointer(regs);
	//const enum reason_type type = get_ins_type(instptr);
	struct dma_sync_trace *trace = p->private;

	/* it doesn't make sense to have more than one active trace per cpu */
	if (my_reason->active_traces)
		die_khwio_nesting_error(regs, addr);
	else
		my_reason->active_traces++;

	//my_reason->type = type;
	my_reason->addr = addr;
	my_reason->ip = instptr;

	my_trace->phys = addr - trace->probe.addr + trace->phys;
	my_trace->virt = addr;
	my_trace->map_id = trace->id;
	my_trace->pc = instptr;

	/*
	 * XXX: the timestamp recorded will be *after* the tracing has been
	 * done, not at the time we hit the instruction. SMP implications
	 * on event ordering?
	 */

	my_trace->opcode = instr->ld ? HWIO_READ : HWIO_WRITE;

	my_trace->width = instr->len;
	if (0 <= instr->rt2 && instr->rt2 <= 31)
		my_trace->width *= 2;

	if (my_trace->opcode == HWIO_WRITE) {
		my_trace->value = regs->regs[instr->rt];
	}

	put_cpu_var(cpu_trace);
	put_cpu_var(pf_reason);
}

static void post(struct khwio_probe *p, unsigned long condition,
		 struct pt_regs *regs, struct Insn *instr)
{
	struct trap_reason *my_reason = &get_cpu_var(pf_reason);
	struct hwiotrace_rw *my_trace = &get_cpu_var(cpu_trace);

	/* this should always return the active_trace count to 0 */
	my_reason->active_traces--;
	if (my_reason->active_traces) {
		pr_emerg("unexpected post handler");
		BUG();
	}

	if (my_trace->opcode == HWIO_READ) {
		my_trace->value = regs->regs[instr->rt];
	}

	hwio_trace_rw(my_trace);
	put_cpu_var(cpu_trace);
	put_cpu_var(pf_reason);
}

#define TRACE_DMA_SYNC_TRACE 0

static int sync_for_cpu_trace_core(void *addr, unsigned long size,
				   unsigned long ctx, bool cacheable)
{
	static atomic_t next_id;
	struct dma_sync_trace *trace;

	struct hwiotrace_map map = { .phys = 0,
				     .virt = (unsigned long)addr,
				     .pc = ctx,
				     .len = size,
				     .opcode = HWIO_PROBE };

	unsigned long flags = GFP_KERNEL;

#if 0
	// TODO: may want to support size larger than PAGE_SIZE
	if (size > PAGE_SIZE) {
		return -EFAULT;
	}
#endif

	if (in_interrupt() || irqs_disabled() || in_atomic())
		flags = GFP_ATOMIC;

	/* These are page-unaligned. */
	trace = kmalloc(sizeof(*trace), flags);

	if (!trace) {
		pr_err("kmalloc failed in sync_for_cpu_trace_core\n");
		return -EFAULT;
	}

#if TRACE_DMA_SYNC_TRACE
	pr_info("sync_for_cpu_trace_core\n");
#endif

	*trace =
		(struct dma_sync_trace){ .probe = { .addr = (unsigned long)addr,
						    .len = size,
						    .ctx = ctx,
						    .pre_handler = pre,
						    .post_handler = post,
						    .cacheable = cacheable,
						    .private = trace },
					 .id = atomic_inc_return(&next_id) };
	map.map_id = trace->id;

	spin_lock_irqsave(&sync_trace_lock, flags);

	hwio_trace_mapping(&map);
	list_add_tail(&trace->list, &sync_trace_list);

#if DMA_SYNC_TRACE_PROBE
	if (!nohwiotrace)
		register_khwio_probe(&trace->probe);
#endif

	spin_unlock_irqrestore(&sync_trace_lock, flags);

	return 0;
}

static void sync_for_device_trace_core(volatile void *addr)
{
	struct hwiotrace_map map = { .phys = 0,
				     .virt = (unsigned long)addr,
				     .pc = 0, // TODO
				     .len = 0,
				     .opcode = HWIO_UNPROBE };
	struct dma_sync_trace *trace;
	struct dma_sync_trace *tmp;
	struct dma_sync_trace *found_trace = NULL;

	unsigned long flags;
	spin_lock_irqsave(&sync_trace_lock, flags);

	list_for_each_entry_safe (trace, tmp, &sync_trace_list, list) {
		if ((unsigned long)addr >= trace->probe.addr &&
		    (unsigned long)addr <
			    trace->probe.addr + trace->probe.len) {
#if DMA_SYNC_TRACE_PROBE
			if (!nohwiotrace)
				unregister_khwio_probe(&trace->probe);
#endif
			list_del(&trace->list);
			found_trace = trace;
			break;
		}
	}
	map.map_id = (found_trace) ? found_trace->id : -1;
	if (found_trace) {
		hwio_trace_mapping(&map);
	}

	spin_unlock_irqrestore(&sync_trace_lock, flags);
	if (found_trace) {
#if TRACE_DMA_SYNC_TRACE
		pr_info("sync_for_device_trace_core found_trace\n");
#endif

		kfree(found_trace);
	}
#if TRACE_DMA_SYNC_TRACE
	else {
		pr_info("sync_for_device_trace_core !found_trace for addr=0x%p\n",
			addr);
	}
#endif
}

#define TRACE_TASK_EVENTS 1

#if TRACE_TASK_EVENTS
static struct hwiotrace_task task;
#endif

void hwiotrace_task_start(void)
{
	if (!is_hwiotrace_enabled())
		return;

#if TRACE_TASK_EVENTS
	task.opcode = HWIO_TASK_START;
	task.task_id = 1; // FIXME
	hwio_trace_task(&task);
#endif

	if (kfuz_hwiotrace_init()) {
#ifdef CONFIG_KCOV
		kcov_hwiotrace_init();
#endif
	}
}

void hwiotrace_task_end(void)
{
	if (!is_hwiotrace_enabled())
		return;

#if TRACE_TASK_EVENTS
	task.opcode = HWIO_TASK_END;
	hwio_trace_task(&task);
#endif

	if (kfuz_hwiotrace_exit()) {
#ifdef CONFIG_KCOV
		kcov_hwiotrace_exit();
#endif
	}
}

/* APIs used by tracefs wrapper */
int hwiotrace_activate_probe(void *addr, unsigned long size, unsigned long ctx,
			     bool cacheable)
{
	return sync_for_cpu_trace_core(addr, size, ctx, cacheable);
}

/* Legacy APIs */
void hwiotrace_sync_single_for_cpu(void *addr, unsigned long size)
{
	sync_for_cpu_trace_core(addr, size, 0, true);
}

void hwiotrace_sync_single_for_device(void *addr)
{
	sync_for_device_trace_core(addr);
}

static void ioremap_trace_core(resource_size_t offset, unsigned long size,
			       void __iomem *addr)
{
	static atomic_t next_id;
	struct remap_trace *trace = kmalloc(sizeof(*trace), GFP_KERNEL);

	/* These are page-unaligned. */
	struct hwiotrace_map map = { .phys = offset,
				     .virt = (unsigned long)addr,
				     .len = size,
				     .opcode = HWIO_PROBE };

	if (!trace) {
		pr_err("kmalloc failed in ioremap\n");
		return;
	}

	*trace = (struct remap_trace){ .probe = { .addr = (unsigned long)addr,
						  .len = size,
						  .pre_handler = pre,
						  .post_handler = post,
						  .private = trace },
				       .phys = offset,
				       .id = atomic_inc_return(&next_id) };
	map.map_id = trace->id;

	spin_lock_irq(&trace_lock);
	if (!is_enabled()) {
		kfree(trace);
		goto not_enabled;
	}

	hwio_trace_mapping(&map);
	list_add_tail(&trace->list, &trace_list);
	if (!nohwiotrace)
		register_khwio_probe(&trace->probe);

not_enabled:
	spin_unlock_irq(&trace_lock);
}

void hwiotrace_ioremap(resource_size_t offset, unsigned long size,
		       void __iomem *addr)
{
	if (!is_enabled()) /* recheck and proper locking in *_core() */
		return;

	if ((filter_offset) && (offset != filter_offset))
		return;
	ioremap_trace_core(offset, size, addr);
}

static void iounmap_trace_core(volatile void __iomem *addr)
{
	struct hwiotrace_map map = { .phys = 0,
				     .virt = (unsigned long)addr,
				     .len = 0,
				     .opcode = HWIO_UNPROBE };
	struct remap_trace *trace;
	struct remap_trace *tmp;
	struct remap_trace *found_trace = NULL;

	spin_lock_irq(&trace_lock);
	if (!is_enabled())
		goto not_enabled;

	list_for_each_entry_safe (trace, tmp, &trace_list, list) {
		if ((unsigned long)addr == trace->probe.addr) {
			if (!nohwiotrace)
				unregister_khwio_probe(&trace->probe);
			list_del(&trace->list);
			found_trace = trace;
			break;
		}
	}
	map.map_id = (found_trace) ? found_trace->id : -1;
	hwio_trace_mapping(&map);

not_enabled:
	spin_unlock_irq(&trace_lock);
	if (found_trace) {
		synchronize_rcu(); /* unregister_khwio_probe() requirement */
		kfree(found_trace);
	}
}

void hwiotrace_iounmap(volatile void __iomem *addr)
{
	might_sleep();
	if (is_enabled()) /* recheck and proper locking in *_core() */
		iounmap_trace_core(addr);
}

int hwiotrace_printk(const char *fmt, ...)
{
	int ret = 0;
	va_list args;
	unsigned long flags;
	va_start(args, fmt);

	spin_lock_irqsave(&trace_lock, flags);
	if (is_enabled())
		ret = hwio_trace_printk(fmt, args);
	spin_unlock_irqrestore(&trace_lock, flags);

	va_end(args);
	return ret;
}

EXPORT_SYMBOL(hwiotrace_printk);

static void clear_trace_list(void)
{
	struct remap_trace *trace;
	struct remap_trace *tmp;

	/*
	 * No locking required, because the caller ensures we are in a
	 * critical section via mutex, and is_enabled() is false,
	 * i.e. nothing can traverse or modify this list.
	 * Caller also ensures is_enabled() cannot change.
	 */
	list_for_each_entry (trace, &trace_list, list) {
		pr_notice(
			"purging non-iounmapped trace @0x%08lx, size 0x%lx.\n",
			trace->probe.addr, trace->probe.len);
		if (!nohwiotrace)
			unregister_khwio_probe(&trace->probe);
	}
	synchronize_rcu(); /* unregister_khwio_probe() requirement */

	list_for_each_entry_safe (trace, tmp, &trace_list, list) {
		list_del(&trace->list);
		kfree(trace);
	}
}

#ifdef CONFIG_HOTPLUG_CPU
static cpumask_var_t downed_cpus;

static int enter_uniprocessor(void)
{
	int cpu;
	int err;

	if (downed_cpus == NULL &&
	    !alloc_cpumask_var(&downed_cpus, GFP_KERNEL)) {
		pr_notice("Failed to allocate mask\n");
		goto out;
	}

	get_online_cpus();
	cpumask_copy(downed_cpus, cpu_online_mask);
	cpumask_clear_cpu(cpumask_first(cpu_online_mask), downed_cpus);
	if (num_online_cpus() > 1)
		pr_notice("Disabling non-boot CPUs...\n");
	put_online_cpus();

	for_each_cpu (cpu, downed_cpus) {
		err = cpu_down(cpu);
		if (!err)
			pr_info("CPU%d is down.\n", cpu);
		else
			pr_err("Error taking CPU%d down: %d\n", cpu, err);
	}
out:
	if (num_online_cpus() > 1) {
		pr_warning("multiple CPUs still online, may miss events.\n");
		return -1;
	}
	return 0;
}

/* __ref because leave_uniprocessor calls cpu_up which is __cpuinit,
   but this whole function is ifdefed CONFIG_HOTPLUG_CPU */
static void __ref leave_uniprocessor(void)
{
	int cpu;
	int err;

	if (downed_cpus == NULL || cpumask_weight(downed_cpus) == 0)
		return;
	pr_notice("Re-enabling CPUs...\n");
	for_each_cpu (cpu, downed_cpus) {
		err = cpu_up(cpu);
		if (!err)
			pr_info("enabled CPU%d.\n", cpu);
		else
			pr_err("cannot re-enable CPU%d: %d\n", cpu, err);
	}
}

#else /* !CONFIG_HOTPLUG_CPU */
static int enter_uniprocessor(void)
{
	if (num_online_cpus() > 1) {
		pr_warning("multiple CPUs are online, may miss events. "
			   "Suggest booting with maxcpus=1 kernel argument.\n");
		return -1;
	}
	return 0;
}

static void leave_uniprocessor(void)
{
}
#endif

bool is_hwiotrace_enabled(void)
{
	return atomic_read(&hwiotrace_enabled);
}

void enable_hwiotrace(void)
{
	mutex_lock(&hwiotrace_mutex);
	if (is_enabled())
		goto out;

	khwio_init();
	if (enter_uniprocessor() != 0)
		goto out;
	spin_lock_irq(&trace_lock);
	atomic_inc(&hwiotrace_enabled);
	spin_unlock_irq(&trace_lock);
out:
	mutex_unlock(&hwiotrace_mutex);
}

void activate_hwiotrace(const char *dev, int dma_sync, int dma_map, int mmio)
{
	mutex_lock(&hwiotrace_mutex);
	if (!is_enabled() || !dev)
		goto out;

	spin_lock_irq(&trace_lock);
	if (dma_sync) {
		dma_flag = HWIOTRACE_DMA_SYNC;
		dma_dev = dev;
	} else if (dma_map) {
		dma_flag = HWIOTRACE_DMA_MAP;
		dma_dev = dev;
	}
	spin_unlock_irq(&trace_lock);
	pr_info("enabled (dev=%s, dma_sync=%d, dma_map=%d, mmio=%d).\n", dev,
		dma_sync, dma_map, mmio);

out:
	mutex_unlock(&hwiotrace_mutex);
}

void disable_hwiotrace(void)
{
	mutex_lock(&hwiotrace_mutex);
	if (!is_enabled())
		goto out;

	if (dma_dev)
		dma_dev = NULL;

	spin_lock_irq(&trace_lock);
	atomic_dec(&hwiotrace_enabled);
	BUG_ON(is_enabled());
	spin_unlock_irq(&trace_lock);

	clear_trace_list(); /* guarantees: no more khwio callbacks */
	leave_uniprocessor();
	khwio_cleanup();
	pr_info("disabled.\n");
out:
	mutex_unlock(&hwiotrace_mutex);
}
