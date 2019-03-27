/*
 * HW I/O tracing
 */

#define DEBUG 1

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/time.h>

#include <linux/atomic.h>

#include "trace.h"
#include "trace_output.h"

struct header_iter {
	struct pci_dev *dev;
};

#define TRACE_HWIO_WLAN 0x1

#define TRACE_HWIO_MMIO 0x10

#define TRACE_HWIO_DMA_SYNC 0x100
#define TRACE_HWIO_DMA_MAP 0x200

static struct tracer_opt trace_opts[] = {
	/* Trace MMIO */
	{ TRACER_OPT(hwio - mmio, TRACE_HWIO_MMIO) },
	/* Trace DMA */
	{ TRACER_OPT(hwio - dma - sync, TRACE_HWIO_DMA_SYNC) },
	{ TRACER_OPT(hwio - dma - map, TRACE_HWIO_DMA_MAP) },
	/* Trace WLAN ? */
	{ TRACER_OPT(hwio - wlan, TRACE_HWIO_WLAN) },
	{} /* Empty entry */
};

static struct tracer_flags tracer_flags = {
	/* Don't trace anything by default */
	.val = 0x0,
	.opts = trace_opts
};

static struct trace_array *hwio_trace_array;
static bool overrun_detected;
static unsigned long prev_overruns;
static atomic_t dropped_count;
static int ftrace_hwio_dma_sync;
static int ftrace_hwio_dma_map;
static int ftrace_hwio_mmio;

static void hwio_reset_data(struct trace_array *tr)
{
	overrun_detected = false;
	prev_overruns = 0;

	tracing_reset_online_cpus(&tr->trace_buffer);
}

static void hwio_trace_start(struct trace_array *tr)
{
	pr_debug("in %s\n", __func__);
	hwio_reset_data(tr);
}

static void hwio_print_pcidev(struct trace_seq *s, const struct pci_dev *dev)
{
	int i;
	resource_size_t start, end;
	const struct pci_driver *drv = pci_dev_driver(dev);
	struct dma_sync_trace *trace;
	struct dma_sync_trace *tmp;
	struct list_head *trace_list;
	unsigned long flags;
	unsigned long long t = 0; //ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(t, USEC_PER_SEC);
	unsigned secs = (unsigned long)t;

	trace_seq_printf(s, "PCIDEV %02x%02x %04x%04x %x", dev->bus->number,
			 dev->devfn, dev->vendor, dev->device, dev->irq);

	// print all DMA buffers currently mapped
	trace_list = sync_trace_list_get(&flags);
	list_for_each_entry_safe (trace, tmp, trace_list, list) {
		trace_seq_printf(
			s,
			"MAP %u.%06lu %ld 0x%llx 0x%lx 0x%lx 0x%lx 0x%lx %d\n",
			secs, usec_rem, trace->id,
			(unsigned long long)trace->phys, trace->probe.addr,
			trace->probe.len, trace->probe.ctx, 0UL, 0);
	}
	sync_trace_list_put(flags);

	/*
	 * XXX: is pci_resource_to_user() appropriate, since we are
	 * supposed to interpret the __ioremap() phys_addr argument based on
	 * these printed values?
	 */
	for (i = 0; i < 7; i++) {
		pci_resource_to_user(dev, i, &dev->resource[i], &start, &end);
		trace_seq_printf(s, " %llx",
				 (unsigned long long)(start |
						      (dev->resource[i].flags &
						       PCI_REGION_FLAG_MASK)));
	}
	for (i = 0; i < 7; i++) {
		pci_resource_to_user(dev, i, &dev->resource[i], &start, &end);
		trace_seq_printf(s, " %llx",
				 dev->resource[i].start < dev->resource[i].end ?
					 (unsigned long long)(end - start) + 1 :
					 0);
	}
	if (drv)
		trace_seq_printf(s, " %s\n", drv->name);
	else
		trace_seq_puts(s, " \n");
}

static void destroy_header_iter(struct header_iter *hiter)
{
	if (!hiter)
		return;
	pci_dev_put(hiter->dev);
	kfree(hiter);
}

static void hwio_pipe_open(struct trace_iterator *iter)
{
	struct header_iter *hiter;
	struct trace_seq *s = &iter->seq;

	trace_seq_puts(s, "VERSION 20180114\n");

	hiter = kzalloc(sizeof(*hiter), GFP_KERNEL);
	if (!hiter)
		return;

	hiter->dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, NULL);
	iter->private = hiter;
}

/* XXX: This is not called when the pipe is closed! */
static void hwio_close(struct trace_iterator *iter)
{
	struct header_iter *hiter = iter->private;
	destroy_header_iter(hiter);
	iter->private = NULL;
}

static unsigned long count_overruns(struct trace_iterator *iter)
{
	unsigned long cnt = atomic_xchg(&dropped_count, 0);
	unsigned long over = ring_buffer_overruns(iter->trace_buffer->buffer);

	if (over > prev_overruns)
		cnt += over - prev_overruns;
	prev_overruns = over;
	return cnt;
}

static ssize_t hwio_read(struct trace_iterator *iter, struct file *filp,
			 char __user *ubuf, size_t cnt, loff_t *ppos)
{
	ssize_t ret;
	struct header_iter *hiter = iter->private;
	struct trace_seq *s = &iter->seq;
	unsigned long n;

	n = count_overruns(iter);
	if (n) {
		/* XXX: This is later than where events were lost. */
		trace_seq_printf(s, "MARK 0.000000 Lost %lu events.\n", n);
		if (!overrun_detected)
			pr_warning("hwiotrace has lost events.\n");
		overrun_detected = true;
		goto print_out;
	}

	if (!hiter)
		return 0;

	hwio_print_pcidev(s, hiter->dev);
	hiter->dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, hiter->dev);

	if (!hiter->dev) {
		destroy_header_iter(hiter);
		iter->private = NULL;
	}

print_out:
	ret = trace_seq_to_user(s, ubuf, cnt);
	return (ret == -EBUSY) ? 0 : ret;
}

static enum print_line_t hwio_print_rw(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct trace_hwiotrace_rw *field;
	struct hwiotrace_rw *rw;
	struct trace_seq *s = &iter->seq;
	unsigned long long t = ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(t, USEC_PER_SEC);
	unsigned secs = (unsigned long)t;

	trace_assign_type(field, entry);
	rw = &field->rw;

	switch (rw->opcode) {
	case HWIO_READ:
		trace_seq_printf(
			s, "R %d %u.%06lu %d 0x%llx 0x%lx 0x%lx 0x%lx %d\n",
			rw->width, secs, usec_rem, rw->map_id,
			(unsigned long long)rw->phys, rw->virt, rw->value,
			rw->pc, 0);
		break;
	case HWIO_WRITE:
		trace_seq_printf(
			s, "W %d %u.%06lu %d 0x%llx 0x%lx 0x%lx 0x%lx %d\n",
			rw->width, secs, usec_rem, rw->map_id,
			(unsigned long long)rw->phys, rw->virt, rw->value,
			rw->pc, 0);
		break;
	case HWIO_UNKNOWN_OP:
		trace_seq_printf(s,
				 "UNKNOWN %u.%06lu %d 0x%llx %02lx,%02lx,"
				 "%02lx 0x%lx %d\n",
				 secs, usec_rem, rw->map_id,
				 (unsigned long long)rw->phys,
				 (rw->value >> 16) & 0xff,
				 (rw->value >> 8) & 0xff,
				 (rw->value >> 0) & 0xff, rw->pc, 0);
		break;
	default:
		trace_seq_puts(s, "rw what?\n");
		break;
	}

	return trace_handle_return(s);
}

static enum print_line_t hwio_print_map(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct trace_hwiotrace_map *field;
	struct hwiotrace_map *m;
	struct trace_seq *s = &iter->seq;
	unsigned long long t = ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(t, USEC_PER_SEC);
	unsigned secs = (unsigned long)t;

	trace_assign_type(field, entry);
	m = &field->map;

	switch (m->opcode) {
	case HWIO_PROBE:
		trace_seq_printf(
			s,
			"MAP %u.%06lu %d 0x%llx 0x%lx 0x%lx 0x%lx 0x%lx %d\n",
			secs, usec_rem, m->map_id, (unsigned long long)m->phys,
			m->virt, m->len, m->pc, 0UL, 0);
		break;
	case HWIO_UNPROBE:
		trace_seq_printf(s, "UNMAP %u.%06lu %d 0x%lx %d\n", secs,
				 usec_rem, m->map_id, 0UL, 0);
		break;
	default:
		trace_seq_puts(s, "map what?\n");
		break;
	}

	return trace_handle_return(s);
}

static enum print_line_t hwio_print_task(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct trace_hwiotrace_task *field;
	struct hwiotrace_task *tsk;
	struct trace_seq *s = &iter->seq;
	unsigned long long t = ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(t, USEC_PER_SEC);
	unsigned secs = (unsigned long)t;

	trace_assign_type(field, entry);
	tsk = &field->task;

	switch (tsk->opcode) {
	case HWIO_TASK_START:
		trace_seq_printf(s, "START %u.%06lu %d\n", secs, usec_rem,
				 tsk->task_id);
		break;
	case HWIO_TASK_END:
		trace_seq_printf(s, "END %u.%06lu %d\n", secs, usec_rem,
				 tsk->task_id);
		break;
	default:
		trace_seq_puts(s, "task what?\n");
		break;
	}

	return trace_handle_return(s);
}

static enum print_line_t hwio_print_mark(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct print_entry *print = (struct print_entry *)entry;
	const char *msg = print->buf;
	struct trace_seq *s = &iter->seq;
	unsigned long long t = ns2usecs(iter->ts);
	unsigned long usec_rem = do_div(t, USEC_PER_SEC);
	unsigned secs = (unsigned long)t;

	/* The trailing newline must be in the message. */
	trace_seq_printf(s, "MARK %u.%06lu %s", secs, usec_rem, msg);

	return trace_handle_return(s);
}

static enum print_line_t hwio_print_line(struct trace_iterator *iter)
{
	switch (iter->ent->type) {
	case TRACE_HWIO_RW:
		return hwio_print_rw(iter);
	case TRACE_HWIO_MAP:
		return hwio_print_map(iter);
	case TRACE_HWIO_TASK:
		return hwio_print_task(iter);
	case TRACE_PRINT:
		return hwio_print_mark(iter);
	default:
		return TRACE_TYPE_HANDLED; /* ignore unknown entries */
	}
}

// reset tracing for current dev
static void hwio_trace_reset_dev(void)
{
	disable_hwiotrace();
}

static void hwio_trace_init_dev(char *dev)
{
	hwio_trace_reset_dev();

	activate_hwiotrace(dev, ftrace_hwio_dma_sync, ftrace_hwio_dma_map,
			   ftrace_hwio_mmio);
}

#define WLAN_DRIVER_NAME "icnss"

static void ftrace_hwio_wlan(int set)
{
	if (set) {
		hwio_trace_init_dev(WLAN_DRIVER_NAME);
	} else {
		hwio_trace_reset_dev();
	}
}

static int hwio_set_flag(struct trace_array *tr, u32 old_flags, u32 bit,
			 int set)
{
	if (bit == TRACE_HWIO_DMA_SYNC)
		ftrace_hwio_dma_sync = set;

	if (bit == TRACE_HWIO_DMA_MAP)
		ftrace_hwio_dma_map = set;

	if (bit == TRACE_HWIO_MMIO)
		ftrace_hwio_mmio = set;

	if (bit == TRACE_HWIO_WLAN)
		ftrace_hwio_wlan(set);

	return 0;
}

static void __trace_hwiotrace_rw(struct trace_array *tr,
				 struct trace_array_cpu *data,
				 struct hwiotrace_rw *rw)
{
	struct trace_event_call *call = &event_hwiotrace_rw;
	struct ring_buffer *buffer = tr->trace_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_hwiotrace_rw *entry;
	int pc = preempt_count();

	event = trace_buffer_lock_reserve(buffer, TRACE_HWIO_RW, sizeof(*entry),
					  0, pc);
	if (!event) {
		atomic_inc(&dropped_count);
		return;
	}
	entry = ring_buffer_event_data(event);
	entry->rw = *rw;

	if (!call_filter_check_discard(call, entry, buffer, event))
		trace_buffer_unlock_commit(tr, buffer, event, 0, pc);
}

void hwio_trace_rw(struct hwiotrace_rw *rw)
{
	struct trace_array *tr = hwio_trace_array;
	struct trace_array_cpu *data =
		per_cpu_ptr(tr->trace_buffer.data, smp_processor_id());
	__trace_hwiotrace_rw(tr, data, rw);
}

static void __trace_hwiotrace_map(struct trace_array *tr,
				  struct trace_array_cpu *data,
				  struct hwiotrace_map *map)
{
	struct trace_event_call *call = &event_hwiotrace_map;
	struct ring_buffer *buffer = tr->trace_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_hwiotrace_map *entry;
	int pc = preempt_count();

	event = trace_buffer_lock_reserve(buffer, TRACE_HWIO_MAP,
					  sizeof(*entry), 0, pc);
	if (!event) {
		atomic_inc(&dropped_count);
		return;
	}
	entry = ring_buffer_event_data(event);
	entry->map = *map;

	if (!call_filter_check_discard(call, entry, buffer, event))
		trace_buffer_unlock_commit(tr, buffer, event, 0, pc);
}

void hwio_trace_mapping(struct hwiotrace_map *map)
{
	struct trace_array *tr = hwio_trace_array;
	struct trace_array_cpu *data;

	preempt_disable();
	data = per_cpu_ptr(tr->trace_buffer.data, smp_processor_id());
	__trace_hwiotrace_map(tr, data, map);
	preempt_enable();
}

static void __trace_hwiotrace_task(struct trace_array *tr,
				   struct trace_array_cpu *data,
				   struct hwiotrace_task *task)
{
	struct trace_event_call *call = &event_hwiotrace_task;
	struct ring_buffer *buffer = tr->trace_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_hwiotrace_task *entry;
	int pc = preempt_count();

	event = trace_buffer_lock_reserve(buffer, TRACE_HWIO_TASK,
					  sizeof(*entry), 0, pc);
	if (!event) {
		atomic_inc(&dropped_count);
		return;
	}
	entry = ring_buffer_event_data(event);
	entry->task = *task;

	if (!call_filter_check_discard(call, entry, buffer, event))
		trace_buffer_unlock_commit(tr, buffer, event, 0, pc);
}

void hwio_trace_task(struct hwiotrace_task *task)
{
	struct trace_array *tr = hwio_trace_array;
	struct trace_array_cpu *data;

	preempt_disable();
	data = per_cpu_ptr(tr->trace_buffer.data, smp_processor_id());
	__trace_hwiotrace_task(tr, data, task);
	preempt_enable();
}

int hwio_trace_printk(const char *fmt, va_list args)
{
	return trace_vprintk(0, fmt, args);
}

static struct trace_parser drv_set_parser;
static struct trace_parser drv_unset_parser;
static struct trace_parser id_set_parser;
static struct trace_parser id_unset_parser;
static struct trace_parser ctx_set_parser;
static struct trace_parser ctx_unset_parser;

/////////////////////////////////////////////////////////////////////////////////////
// SHOW ACTIVE MAPPINGS /////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
static int mappings_avail_seq_show(struct seq_file *s, void *v)
{
	struct list_head *mappings;
	struct hwiotrace_mapping *am;
	unsigned long flags;

	seq_printf(s, "ID NAME CTX VA SIZE STATE\n");
	mappings = hwiotrace_mappings_get(&flags);
	list_for_each_entry (am, mappings, list_glob) {
		seq_printf(s, "%zu %s 0x%lx %lx %ld %s\n", am->map_id,
			   am->pp->drv_name, am->pp->ctx, (unsigned long)am->va,
			   am->size, am->tracing ? "TRACING" : "-");
	}
	hwiotrace_mappings_put(flags);
	return 0;
}
static int mappings_avail_open(struct inode *inode, struct file *file)
{
	return single_open(file, mappings_avail_seq_show, 0);
}
static const struct file_operations mappings_avail_fops = {
	.open = mappings_avail_open,
	.read = seq_read,
	.release = single_release,
};

/////////////////////////////////////////////////////////////////////////////////////
// SHOW AVAILABLE PROBES ////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
static int probes_avail_seq_show(struct seq_file *s, void *v)
{
	struct list_head *probes;
	struct hwiotrace_probe *p;
	unsigned long flags;

	seq_printf(s, "ID NAME CTX TYPE SIZE STATE\n");
	probes = hwiotrace_probes_get(&flags);
	list_for_each_entry (p, probes, list) {
		seq_printf(s, "%zu %s 0x%lx %s %ld %s\n", p->id, p->drv_name,
			   p->ctx, probe_type_names[p->type], p->last_length,
			   p->tracing ? "TRACING" : "-");
	}
	hwiotrace_probes_put(flags);
	return 0;
}
static int probes_avail_open(struct inode *inode, struct file *file)
{
	return single_open(file, probes_avail_seq_show, 0);
}
static const struct file_operations probes_avail_fops = {
	.open = probes_avail_open,
	.read = seq_read,
	.release = single_release,
};

static int filter_open(struct inode *inode, struct file *file)
{
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
// ID FILTER ////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
ssize_t id_set_filter_write(struct file *file, const char __user *ubuf,
			    size_t cnt, loff_t *ppos)
{
	size_t read, id;
	read = trace_get_user(&id_set_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&id_set_parser) &&
	    !trace_parser_cont(&id_set_parser)) {
		if (kstrtoul(id_set_parser.buffer, 10, &id) == 0)
			activate_hwiotrace_probe(NULL, 0, id);
	}
	return read;
}
ssize_t id_unset_filter_write(struct file *file, const char __user *ubuf,
			      size_t cnt, loff_t *ppos)
{
	size_t read, id;
	read = trace_get_user(&id_unset_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&id_unset_parser) &&
	    !trace_parser_cont(&id_unset_parser)) {
		if (kstrtoul(id_unset_parser.buffer, 10, &id) == 0)
			deactivate_hwiotrace_probe(NULL, 0, id);
	}
	return read;
}
static const struct file_operations id_set_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = id_set_filter_write,
};
static const struct file_operations id_unset_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = id_unset_filter_write,
};

/////////////////////////////////////////////////////////////////////////////////////
// CTX FILTER ///////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
ssize_t ctx_set_filter_write(struct file *file, const char __user *ubuf,
			     size_t cnt, loff_t *ppos)
{
	size_t read;
	unsigned long ctx;
	read = trace_get_user(&ctx_set_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&ctx_set_parser) &&
	    !trace_parser_cont(&ctx_set_parser)) {
		if (kstrtoul(ctx_set_parser.buffer, 16, &ctx) == 0)
			activate_hwiotrace_probe(NULL, ctx, 0);
	}
	return read;
}
ssize_t ctx_unset_filter_write(struct file *file, const char __user *ubuf,
			       size_t cnt, loff_t *ppos)
{
	size_t read;
	unsigned long ctx;
	read = trace_get_user(&ctx_unset_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&ctx_unset_parser) &&
	    !trace_parser_cont(&ctx_unset_parser)) {
		if (kstrtoul(ctx_unset_parser.buffer, 16, &ctx) == 0)
			deactivate_hwiotrace_probe(NULL, ctx, 0);
	}
	return read;
}
static const struct file_operations ctx_set_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = ctx_set_filter_write,
};
static const struct file_operations ctx_unset_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = ctx_unset_filter_write,
};

/////////////////////////////////////////////////////////////////////////////////////
// DRV FILTER ///////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
ssize_t drv_set_filter_write(struct file *file, const char __user *ubuf,
			     size_t cnt, loff_t *ppos)
{
	size_t read;
	read = trace_get_user(&drv_set_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&drv_set_parser) &&
	    !trace_parser_cont(&drv_set_parser)) {
		activate_hwiotrace_probe(drv_set_parser.buffer, 0, 0);
	}
	return read;
}
ssize_t drv_unset_filter_write(struct file *file, const char __user *ubuf,
			       size_t cnt, loff_t *ppos)
{
	size_t read;
	read = trace_get_user(&drv_unset_parser, ubuf, cnt, ppos);
	if (read >= 0 && trace_parser_loaded(&drv_unset_parser) &&
	    !trace_parser_cont(&drv_unset_parser)) {
		deactivate_hwiotrace_probe(drv_set_parser.buffer, 0, 0);
	}
	return read;
}
static const struct file_operations drv_set_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = drv_set_filter_write,
};
static const struct file_operations drv_unset_filter_fops = {
	.open = filter_open,
	.read = seq_read,
	.write = drv_unset_filter_write,
};

/////////////////////////////////////////////////////////////////////////////////////
// INITALIZER ///////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

#define MAX_FILTER_SIZE 1024

static int init_tracer_fs(struct trace_array *tr)
{
	struct dentry *t_options = tr->options; //trace_options_init_dentry(tr);
	if (!t_options) {
		pr_err("Error init_tracer_fs no options directory\n");
	}

	debugfs_create_file("hwio_available_mappings", 0444, t_options, tr,
			    &mappings_avail_fops);

	debugfs_create_file("hwio_available_probes", 0444, t_options, tr,
			    &probes_avail_fops);

	debugfs_create_file("hwio_drv_set_filter", 0644, t_options, tr,
			    &drv_set_filter_fops);
	debugfs_create_file("hwio_drv_unset_filter", 0644, t_options, tr,
			    &drv_unset_filter_fops);

	debugfs_create_file("hwio_id_set_filter", 0644, t_options, tr,
			    &id_set_filter_fops);
	debugfs_create_file("hwio_id_unset_filter", 0644, t_options, tr,
			    &id_unset_filter_fops);

	debugfs_create_file("hwio_ctx_set_filter", 0644, t_options, tr,
			    &ctx_set_filter_fops);
	debugfs_create_file("hwio_ctx_unset_filter", 0644, t_options, tr,
			    &ctx_unset_filter_fops);

	trace_parser_get_init(&drv_set_parser, MAX_FILTER_SIZE);
	trace_parser_get_init(&drv_unset_parser, MAX_FILTER_SIZE);

	trace_parser_get_init(&id_set_parser, MAX_FILTER_SIZE);
	trace_parser_get_init(&id_unset_parser, MAX_FILTER_SIZE);

	trace_parser_get_init(&ctx_set_parser, MAX_FILTER_SIZE);
	trace_parser_get_init(&ctx_unset_parser, MAX_FILTER_SIZE);

	return 0;
}

// TODO: should remove debugfs option files here but don't know how
static int reset_tracer_fs(struct trace_array *tr)
{
	stop_all_hwiotrace_probes();
	return 0;
}

static int hwio_trace_init(struct trace_array *tr)
{
	pr_debug("in %s\n", __func__);
	hwio_trace_array = tr;

	hwio_reset_data(tr);
	enable_hwiotrace();
	init_tracer_fs(hwio_trace_array);
	return 0;
}

static void hwio_trace_reset(struct trace_array *tr)
{
	pr_debug("in %s\n", __func__);

	reset_tracer_fs(tr);
	hwio_reset_data(tr);
	hwio_trace_array = NULL;
}

/**
 * struct tracer - a specific tracer and its callbacks to interact with tracefs
 * @name: the name chosen to select it on the available_tracers file
 * @init: called when one switches to this tracer (echo name > current_tracer)
 * @reset: called when one switches to another tracer
 * @start: called when tracing is unpaused (echo 1 > tracing_enabled)
 * @stop: called when tracing is paused (echo 0 > tracing_enabled)
 * @update_thresh: called when tracing_thresh is updated
 * @open: called when the trace file is opened
 * @pipe_open: called when the trace_pipe file is opened
 * @close: called when the trace file is released
 * @pipe_close: called when the trace_pipe file is released
 * @read: override the default read callback on trace_pipe
 * @splice_read: override the default splice_read callback on trace_pipe
 * @selftest: selftest to run on boot (see trace_selftest.c)
 * @print_headers: override the first lines that describe your columns
 * @print_line: callback that prints a trace
 * @set_flag: signals one of your private flags changed (trace_options file)
 * @flags: your private flags
 */

static struct tracer hwio_tracer __read_mostly = {
	.name = "hwiotrace",
	.init = hwio_trace_init,
	.reset = hwio_trace_reset,
	.start = hwio_trace_start,
	.pipe_open = hwio_pipe_open,
	.close = hwio_close,
	.read = hwio_read,
	.print_line = hwio_print_line,
	.flags = &tracer_flags,
	.set_flag = hwio_set_flag,
};

__init static int init_hwio_trace(void)
{
	return register_tracer(&hwio_tracer);
}

device_initcall(init_hwio_trace);
