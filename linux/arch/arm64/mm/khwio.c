/*
 * Extended kmmio.c for arm64 and DMA support
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/hash.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
#include <linux/kcov.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/preempt.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/debug-monitors.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <linux/errno.h>
#include <linux/hwiotrace.h>
#include <linux/hwiofuzz.h>
#include <linux/decode.h>
#include "decode_helper.h"

#define KHWIO_PAGE_HASH_BITS 4
#define KHWIO_PAGE_TABLE_SIZE (1 << KHWIO_PAGE_HASH_BITS)

#define SINGLE_STEP_ORIG_INSTR 1
#define EMULATE_STR 0
#define RETURN_NULL_PTE_LOOKUP 0
#define SPLIT_FAULT_PAGE_PMDS 1
#define ARM_FAULT_PAGE 1
#define ADD_FAULT_PAGE 1
#define ADD_PROBES 1
#define DELAYED_RELEASE                                                        \
	0 // NOT supported. May not be necessary in uniprocessor env.
#define UNREGISTER_DISABLED 0
#define ATOMIC_KMALLOC 1
#define ENABLE_HWIOTRACE_HANDLERS 1

struct khwio_fault_page {
	struct list_head list;
	struct khwio_fault_page *release_next;
	unsigned long addr; /* the requested address */
	pteval_t old_presence; /* page presence prior to arming */
	bool armed;
	unsigned long long *mapped_ptr;

	/*
	 * Number of times this page has been registered as a part
	 * of a probe. If zero, page is disarmed and this may be freed.
	 * Used only by writers (RCU) and post_khwio_handler().
	 * Protected by khwio_lock, when linked into khwio_page_table.
	 */
	int count;

	bool scheduled_for_release;
};

#if DELAYED_RELEASE
struct khwio_delayed_release {
	struct rcu_head rcu;
	struct khwio_fault_page *release_list;
};
#endif

struct khwio_context {
	struct khwio_fault_page *fpage[2];
	struct khwio_probe *probe;
	unsigned long saved_flags;
	struct Insn instr;
	unsigned long addr;
	bool decoded;
	int active;
};

static DEFINE_SPINLOCK(khwio_lock);

/* Protected by khwio_lock */
unsigned int khwio_count;
void *khwio_insn_page;
unsigned long khwio_saved_irqflag;
struct khwio_decode_ctx kd;
struct pt_regs fault_regs;
struct pt_regs khwio_regs;
unsigned long targeted_fn_addr;
unsigned long targeted_fn_size;

/* Read-protected by RCU, write-protected by khwio_lock. */
static struct list_head khwio_page_table[KHWIO_PAGE_TABLE_SIZE];
static LIST_HEAD(khwio_probes);

#define TRACE_LOOKUP_ADDRESS 0
#define PT_LEVEL_PUD 1
#define PT_LEVEL_PMD 2
#define PT_LEVEL_PTE 3
/*
 * Check whether a kernel address is valid.
 */
pte_t *lookup_address(unsigned long addr, unsigned int *level)
{
#if RETURN_NULL_PTE_LOOKUP
	return 0;
#else
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if ((((long)addr) >> VA_BITS) != -1UL)
		return 0;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd)) {
		pr_err("lookup_address pgd_none\n");
		return 0;
	}

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		pr_err("lookup_address pud_none\n");
		return 0;
	}

	if (pud_sect(*pud)) {
		pr_info("lookup_address pud_sect pud_val(*pud)=0x%llx\n",
			pud_val(*pud));
		if (level)
			*level = PT_LEVEL_PUD;
		return (pte_t *)pud;
	}

	if (pud_bad(*pud)) {
		pr_err("lookup_address pud_bad pud_val(*pud)=0x%llx\n",
		       pud_val(*pud));
		return 0;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		pr_err("lookup_address pmd_none\n");
		return 0;
	}

	if (pmd_sect(*pmd)) {
		pr_info("lookup_address pmd_sect pmd_val(*pmd)=0x%llx\n",
			pmd_val(*pmd));
		if (level)
			*level = PT_LEVEL_PMD;
		return pmd;
	}

	if (pmd_bad(*pmd)) {
		pr_err("lookup_address pmd_bad pmd_val(*pmd)=0x%llx\n",
		       pmd_val(*pmd));
		return 0;
	}

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte)) {
		pr_err("lookup_address pte_none pgd_val(*pgd)=0x%llx pmd_val(*pmd)=0x%llx pte_val(*pte)=0x%llx\n",
		       pgd_val(*pgd), pmd_val(*pmd), pte_val(*pte));
		return 0;
	}

#if TRACE_LOOKUP_ADDRESS
	pr_info("lookup_address pte_val(*pte)=0x%llx\n", pte_val(*pte));
#endif

	if (level)
		*level = PT_LEVEL_PTE;
	return pte;
#endif
}

#define TRACE_PAGE_LIST_MGMT 0
static struct list_head *khwio_page_list(unsigned long addr)
{
	unsigned int l;
	pte_t *pte = lookup_address(addr, &l);

#if TRACE_PAGE_LIST_MGMT
	pr_info("khwio_page_list addr=0x%llx\n", addr);
#endif

	if (!pte)
		return NULL;
	addr &= PAGE_MASK;

	return &khwio_page_table[hash_long(addr, KHWIO_PAGE_HASH_BITS)];
}

/* Accessed per-cpu */
static DEFINE_PER_CPU(struct khwio_context, khwio_ctx);

static struct khwio_probe *get_khwio_probe(unsigned long addr)
{
	struct khwio_probe *p;
	struct khwio_probe *tmp;

	//pr_info("get_khwio_probe addr=0x%llx\n", addr);

#if !DELAYED_RELEASE
	list_for_each_entry_safe (p, tmp, &khwio_probes, list) {
#else
	list_for_each_entry_rcu (p, &khwio_probes, list) {
#endif
		if (addr >= p->addr && addr < (p->addr + p->len))
			return p;
	}
	return NULL;
}

static struct khwio_fault_page *get_khwio_fault_page(unsigned long addr)
{
	struct list_head *head;
	struct khwio_fault_page *f;
	struct khwio_fault_page *tmp;
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (!pte)
		return NULL;

	addr &= PAGE_MASK;
	head = khwio_page_list(addr);
#if !DELAYED_RELEASE
	list_for_each_entry_safe (f, tmp, head, list) {
#else
	list_for_each_entry_rcu (f, head, list) {
#endif
		if (f->addr == addr)
			return f;
	}

	//pr_info("get_khwio_fault_page NULL\n");

	return NULL;
}

#if SPLIT_FAULT_PAGE_PMDS
static void split_pmd(pmd_t *pmd)
{
	// allocate new pte page table
	pte_t *pte_pt = (pte_t *)kmalloc(PAGE_SIZE, GFP_ATOMIC);
	unsigned long pmd_base_addr;
	unsigned i;

	pr_info("split_pmd 0x%016lx\n", (unsigned long)*pmd);

	BUG_ON(!pte_pt);
	pmd_base_addr = (unsigned long)*pmd & PMD_MASK;

	*pmd = virt_to_phys(pte_pt) | PROT_NORMAL;
	for (i = 0; i < PTRS_PER_PTE; ++i) {
		*pte_pt = pmd_base_addr | PROT_NORMAL;
		pte_pt++;
		pmd_base_addr += PAGE_SIZE;
	}
	flush_tlb_all();
}
#endif

#define SKIP_SINGLE_STEP 1

// Fuzzer hook impl.
static int execute_hooks(struct khwio_probe *probe, struct Insn *instr,
			 struct pt_regs *regs, unsigned long addr,
			 char *mapped_ptr, char *mapped_ptr_bkp)
{
	unsigned int page_offset;
	unsigned int buffer_offset;

	unsigned int amult = 1;
	unsigned int access_len;

	if (0 <= instr->rt2 && instr->rt2 <= 31)
		amult = 2;
	access_len = instr->len * amult;

	// get offset from start of page
	page_offset = addr & ~PAGE_MASK;
	buffer_offset = addr - probe->addr;

	// TODO: only flush required chache lines
	flush_cache_all();

	mapped_ptr = &mapped_ptr[page_offset];

	if (instr->ld) { // instruction is a load register from memory
		char fuzzbuf[16]; // 16 byte == maximum reach of one assembler instruction
		memset(fuzzbuf, 0x0, 16);

		if (probe &&
		    kfuz_hwiotrace_consume(fuzzbuf, probe->addr, buffer_offset,
					   access_len, probe->cacheable)) {
			pr_info("fuzzing ld at 0x%x (+0x%x): 0x%016llx 0x%016llx -> 0x%016llx 0x%016llx\n",
				buffer_offset, access_len,
				*(long long *)mapped_ptr,
				*(long long *)&mapped_ptr[8],
				*(long long *)fuzzbuf,
				*(long long *)&fuzzbuf[8]);
			mapped_ptr = fuzzbuf;
			mapped_ptr_bkp = NULL;
		} else {
			return -1;
		}

		if (emulate_ld(instr, regs, mapped_ptr, mapped_ptr_bkp) != 0) {
			pr_err("emulation failed [%lx] addr=%lx\n",
			       instruction_pointer(regs), addr);
			return -1;
		}

		probe->n_read += 1;
	} else { // instruction is a store register to memory
		// the driver might itself overwrite some data within
		// that mapping at a later point when the device can
		// no longer access the area
		if (probe &&
		    probe->cacheable) { // TODO: check if dma streaming mapping
			kfuz_hwiotrace_mask(probe->addr, buffer_offset,
					    access_len);
		}
#if !EMULATE_STR
		probe->n_write += 1;
		return -1;
#else
		if (emulate_st(instr, regs, mapped_ptr, mapped_ptr_bkp) != 0) {
			pr_err("emulation failed [%llx] addr=%llx\n",
			       instruction_pointer(regs), addr);
			return -1;
		}

		probe->n_write += 1;
#endif
	}

	// TODO selectively flush cache line
	flush_cache_all();
	return SKIP_SINGLE_STEP;
}

#define NO_DECODE_AND_EMULATE 1

#if !NO_DECODE_AND_EMULATE
static int decode_and_emulate(struct khwio_probe *probe, struct pt_regs *regs,
			      unsigned long addr)
{
	// this will be the instruction pointer after emulation
	// we only handle loads and stores, so there should be no jumps
	// get opcode
	uint32_t insn = *(uint32_t *)instruction_pointer(regs);

	unsigned int offset;
	// get index to (long long*) mapped_ptr[PAGE_SIZE * 2]
	unsigned int ptr_idx;
	// get (long long) aligned offset
	unsigned int al_offset;
	unsigned int al_diff;
	unsigned long long mem_data;
	unsigned long long *original_mem_ptr = NULL;
	unsigned long long
		original_mem_buf[4]; // FIXME: should it be larger than 4?

	struct Insn instr;
	struct khwio_fault_page *faultpage =
		get_khwio_fault_page(addr & PAGE_MASK);

	bool manual_fuzzing = false;

	if (targeted_fn_addr != 0UL &&
	    instruction_pointer(regs) >= targeted_fn_addr &&
	    instruction_pointer(regs) < targeted_fn_addr + targeted_fn_size) {
		manual_fuzzing = true;
	}

	if (faultpage->mapped_ptr == NULL) {
		return -EFAULT;
	}

#define PRINT_DECODE_FAILURE 0

	if (arm64_decode(insn, &instr) != 0) {
#if PRINT_DECODE_FAILURE
		pr_err("decoding failed [<0x%llx>] addr=%p insn=%x\n",
		       instruction_pointer(regs), addr, insn);
#endif
		return -EFAULT;
	}

	// get offset from start of page
	offset = addr & ~PAGE_MASK;
	// get index to (long long*) mapped_ptr[PAGE_SIZE * 2]
	ptr_idx = offset / sizeof(unsigned long long);

	original_mem_ptr = faultpage->mapped_ptr + ptr_idx;
	memcpy(original_mem_buf, original_mem_ptr, sizeof(original_mem_buf));
	if (probe && kfuz_hwiotrace_consume(original_mem_ptr, probe->addr,
					    (unsigned long)original_mem_ptr -
						    (unsigned long)probe->addr,
					    sizeof(original_mem_buf),
					    probe->cacheable)) {
		pr_info("fuzzing at 0x%lx! %llx %llx %llx %llx -> %llx %llx %llx %llx\n",
			(unsigned long)original_mem_ptr -
				(unsigned long)probe->addr,
			original_mem_buf[0], original_mem_buf[1],
			original_mem_buf[2], original_mem_buf[3],
			original_mem_ptr[0], original_mem_ptr[1],
			original_mem_ptr[2], original_mem_ptr[3]);
	}

	if (manual_fuzzing) {
		pr_info("manual fuzzing!\n");
		memset(original_mem_ptr, 0xff, sizeof(unsigned long));
	}

	// get (long long) aligned offset
	al_offset = ptr_idx * sizeof(unsigned long long);
	al_diff = offset - al_offset;

	// TODO: only flush required cache lines
	flush_cache_all();

	// get field from memory, instr.len holds number of bytes
	// (can be byte(8), short(16), int(32) or long long(64))
	mem_data = sd_field(faultpage->mapped_ptr[ptr_idx],
			    al_diff * 8, // start of field
			    instr.len); // length of field

	pr_info("decode_and_emulate [<0x%lx>] insn=0x%x addr=0x%lx mem_data=0x%llx *ptr=0x%llx idx=0x%u, ptr=0x%p\n",
		instruction_pointer(regs), insn, addr, mem_data,
		faultpage->mapped_ptr[ptr_idx], ptr_idx, faultpage->mapped_ptr);

	if (instr.ld) { // instruction is a load register from memory
		unsigned long reg_len =
			32; // registers can only be written as int or long long
		unsigned long long new_data;
		if (instr.len > 32)
			reg_len = 64;
		//		regs->regs[instr.rt] = 0;
		new_data = sd_mod_field( // update first 32 bit of the 64bit register
			regs->regs[instr.rt], // TODO: I don't know how to access the second half
			mem_data, 0, reg_len);
		regs->regs[instr.rt] = new_data;

		// handle ldp x1, x2, [mem]
		// ldp and stp only work on 32 or 64 bit
		if (instr.rt2 > 0) {
			if (instr.len == 64) {
				// TODO: this will fail if the probed physical memory is not contigous
				regs->regs[instr.rt2] =
					faultpage->mapped_ptr[ptr_idx + 1];
			} else {
				al_diff += 4;
				if (al_diff > 4) {
					ptr_idx++;
					al_diff = 0;
				}
				mem_data =
					sd_field(faultpage->mapped_ptr[ptr_idx],
						 al_diff * 8, 32);
				//				regs->regs[instr.rt2] = 0;
				new_data = sd_mod_field(regs->regs[instr.rt2],
							mem_data, 0, 32);
				regs->regs[instr.rt2] = new_data;
			}
		}
	} else { // instruction is a store register to memory
#if EMULATE_STR
		unsigned long long new_data =
			sd_mod_field(faultpage->mapped_ptr[ptr_idx],
				     regs->regs[instr.rt], al_diff * 8,
				     instr.len);
		faultpage->mapped_ptr[ptr_idx] = new_data;

		if (instr.rt2 > 0) {
			if (instr.len == 64) {
				faultpage->mapped_ptr[ptr_idx + 1] =
					regs->regs[instr.rt2];
			} else {
				new_data = sd_mod_field(
					faultpage->mapped_ptr[ptr_idx],
					regs->regs[instr.rt2], 32, 32);
				faultpage->mapped_ptr[ptr_idx] = new_data;
			}
		}
#else
		return -1;
#endif
	}

	if (original_mem_ptr != NULL) {
		memcpy(original_mem_ptr, original_mem_buf,
		       sizeof(original_mem_buf));
	}

	// TODO selectively flush cache line
	flush_cache_all();
	return 0;
}
#endif

#if ARM_FAULT_PAGE
static void clear_pte_presence(pte_t *pte, bool clear, pteval_t *old)
{
	pteval_t v = pte_val(*pte);
	if (clear) {
		v &= ~PTE_VALID;
	} else /* presume this has been called with clear==true previously */
		v |= PTE_VALID;
	set_pte(pte, __pte(v));
}

static int clear_page_presence(struct khwio_fault_page *f, bool clear)
{
	unsigned int level;
	pte_t *pte = lookup_address(f->addr, &level);

	if (!pte) {
		pr_err("no pte for addr 0x%08lx\n", f->addr);
		return -1;
	}

	clear_pte_presence(pte, clear, &f->old_presence);

	flush_tlb_kernel_range(f->addr, f->addr + PAGE_SIZE);
	return 0;
}
#endif

#define LOG_ARM_DISARM 0

/*
 * Mark the given page as not present. Access to it will trigger a fault.
 */
static int arm_khwio_fault_page(struct khwio_fault_page *f)
{
	int ret;

#if SPLIT_FAULT_PAGE_PMDS
	unsigned int level;
	pte_t *pte = lookup_address(f->addr, &level);
	if (level == PT_LEVEL_PMD) {
		split_pmd(pte);
		pte = lookup_address(f->addr, &level);
		if (level != PT_LEVEL_PTE) {
			pr_err("split page table did not work for addr 0x%08lx\n",
			       f->addr);
		}
	} else if (level != PT_LEVEL_PTE) {
		pr_err("split page table not implemented for addr 0x%08lx\n",
		       f->addr);
	}
	BUG_ON(level != PT_LEVEL_PTE);
#endif

#if ARM_FAULT_PAGE
	WARN_ONCE(f->armed, KERN_ERR pr_fmt("khwio page already armed.\n"));
	if (f->armed) {
		pr_warning("double-arm: addr 0x%08lx, ref %d, old %d\n",
			   f->addr, f->count, !!f->old_presence);
	}
	ret = clear_page_presence(f, true);
	WARN_ONCE(ret < 0, KERN_ERR pr_fmt("arming at 0x%08lx failed.\n"),
		  f->addr);
#else
	ret = 0;
#endif
#if LOG_ARM_DISARM
	pr_info("arm_khwio_fault_page addr=0x%llx\n", f->addr);
#endif
	f->armed = true;
	return ret;
}

/** Restore the given page to saved presence state. */
static void disarm_khwio_fault_page(struct khwio_fault_page *f)
{
#if ARM_FAULT_PAGE
	int ret = clear_page_presence(f, false);
	WARN_ONCE(ret < 0, KERN_ERR "khwio disarming at 0x%08lx failed.\n",
		  f->addr);
#endif
#if LOG_ARM_DISARM
	pr_info("disarm_khwio_fault_page addr=0x%llx\n", f->addr);
#endif
	f->armed = false;
}

static int post_khwio_handler(unsigned long condition, struct pt_regs *regs)
{
	int ret = 0;
	struct khwio_context *ctx = &get_cpu_var(khwio_ctx);

	//pr_info("post_khwio_handler ctx=0x%llx\n", ctx);

	if (!ctx->active) {
		/*
		 * debug traps without an active context are due to either
		 * something external causing them (f.e. using a debugger while
		 * hwio tracing enabled), or erroneous behaviour
		 */
		pr_emerg("unexpected debug trap on CPU %d.\n",
			 smp_processor_id());
		ret = -1;
		goto out;
	}

#if ENABLE_HWIOTRACE_HANDLERS
	if (ctx->probe && ctx->probe->post_handler && ctx->decoded)
		ctx->probe->post_handler(ctx->probe, condition, regs,
					 &ctx->instr);
#endif

	/* Prevent racing against release_khwio_fault_page(). */
	//spin_lock(&khwio_lock);
	if (ctx->fpage[0] && ctx->fpage[0]->count)
		arm_khwio_fault_page(ctx->fpage[0]);

	if (ctx->fpage[1] && ctx->fpage[1]->count)
		arm_khwio_fault_page(ctx->fpage[1]);
	//spin_unlock(&khwio_lock);

	/* These were acquired in khwio_handler(). */
	ctx->active--;
	BUG_ON(ctx->active);

	if (kd.ainsn.restore != 0) {
		//pr_info("post_khwio_handler restore=0x%llx\n", kd.ainsn.restore);
		regs->pc = kd.ainsn.restore;
	}

#if DELAYED_RELEASE
	rcu_read_unlock();
#endif
	//preempt_enable_no_resched();
	//local_irq_enable();

out:
	put_cpu_var(khwio_ctx);
	return ret;
}

#if !SINGLE_STEP_ORIG_INSTR
static void arch_prepare_ss_slot(struct khwio_decode_ctx *p)
{
	/* prepare insn slot */
	p->ainsn.insn[0] = cpu_to_le32(p->opcode);

	flush_icache_range((uintptr_t)(p->ainsn.insn),
			   (uintptr_t)(p->ainsn.insn) +
				   MAX_INSN_SIZE * sizeof(khwio_opcode_t));

	/*
	 * Needs restoring of return address after stepping xol.
	 */
	p->ainsn.restore = (unsigned long)p->addr + sizeof(khwio_opcode_t);
}

static bool aarch64_insn_is_steppable(u32 insn)
{
	return true;
}

/* Return:
 *   INSN_REJECTED     If instruction is one not allowed to khwio,
 *   INSN_GOOD         If instruction is supported and uses instruction slot,
 *   INSN_GOOD_NO_SLOT If instruction is supported but doesn't use its slot.
 */
static enum khwio_insn
arm_probe_decode_insn(khwio_opcode_t insn, struct khwio_arch_specific_insn *asi)
{
	/*
	 * Instructions reading or modifying the PC won't work from the XOL
	 * slot.
	 */
	if (aarch64_insn_is_steppable(insn))
		return INSN_GOOD;

#if 0
	if (aarch64_insn_is_bcond(insn)) {
		asi->handler = simulate_b_cond;
	} else if (aarch64_insn_is_cbz(insn) ||
	    aarch64_insn_is_cbnz(insn)) {
		asi->handler = simulate_cbz_cbnz;
	} else if (aarch64_insn_is_tbz(insn) ||
	    aarch64_insn_is_tbnz(insn)) {
		asi->handler = simulate_tbz_tbnz;
	} else if (aarch64_insn_is_adr_adrp(insn)) {
		asi->handler = simulate_adr_adrp;
	} else if (aarch64_insn_is_b(insn) ||
	    aarch64_insn_is_bl(insn)) {
		asi->handler = simulate_b_bl;
	} else if (aarch64_insn_is_br(insn) ||
	    aarch64_insn_is_blr(insn) ||
	    aarch64_insn_is_ret(insn)) {
		asi->handler = simulate_br_blr_ret;
	} else if (aarch64_insn_is_ldr_lit(insn)) {
		asi->handler = simulate_ldr_literal;
	} else if (aarch64_insn_is_ldrsw_lit(insn)) {
		asi->handler = simulate_ldrsw_literal;
	} else {
		/*
		 * Instruction cannot be stepped out-of-line and we don't
		 * (yet) simulate it.
		 */
		return INSN_REJECTED;
	}
#endif

	BUG();

	return INSN_GOOD_NO_SLOT;
}

int arch_prepare_hwio_probe(struct khwio_decode_ctx *p, khwio_opcode_t *slot)
{
	unsigned long probe_addr = (unsigned long)p->addr;
	extern char __start_rodata[];
	extern char __end_rodata[];

	if (probe_addr & 0x3)
		return -EINVAL;

	/* copy instruction */
	p->opcode = le32_to_cpu(*p->addr);

	if (in_exception_text(probe_addr))
		return -EINVAL;
	if (probe_addr >= (unsigned long)__start_rodata &&
	    probe_addr <= (unsigned long)__end_rodata)
		return -EINVAL;

	/* decode instruction */
	switch (arm_probe_decode_insn(le32_to_cpu(*p->addr), &p->ainsn)) {
	case INSN_REJECTED: /* insn not supported */
		// TODO: should warn
		return -EINVAL;

	case INSN_GOOD_NO_SLOT: /* insn need simulation */
		p->ainsn.insn = NULL;
		break;

	case INSN_GOOD: /* instruction uses slot */
		p->ainsn.insn = slot;
		if (!p->ainsn.insn)
			return -ENOMEM;
		break;
	};

	/* prepare the instruction */
	if (p->ainsn.insn)
		arch_prepare_ss_slot(p);
	else
#if 1
		BUG();
#else
		arch_prepare_simulate(p);
#endif

	return 0;
}
#endif

#if 0
static int patch_text(khwio_opcode_t *addr, u32 opcode)
{
	void *addrs[1];
	u32 insns[1];

	addrs[0] = (void *)addr;
	insns[0] = (u32)opcode;

	return aarch64_insn_patch_text_nosync(addrs[0], insns[0]);
}
#endif

int khwio_handler(struct pt_regs *regs, unsigned long addr)
{
	struct khwio_context *ctx;
	struct khwio_fault_page *faultpage;
	int ret = 0; /* default to fault not handled */
	unsigned long page_base = addr & PAGE_MASK;
	char symbuf[KSYM_SYMBOL_LEN];
	unsigned long flags;

#if 0
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	if (!pte) {
		pr_err("khwio_handler pte does not exist pc=0x%llx addr=0x%llx\n", instruction_pointer(regs), addr);
		return -EINVAL;
	}
#endif

	local_irq_save(flags);
	local_irq_disable();
	//preempt_disable();
	//spin_lock_irqsave(&khwio_lock, flags);
#if DELAYED_RELEASE
	rcu_read_lock();
#endif

	faultpage = get_khwio_fault_page(page_base);
	if (!faultpage) {
		goto no_khwio;
	}

	sprint_symbol(symbuf, instruction_pointer(regs));

	ctx = &get_cpu_var(khwio_ctx);
	if (ctx->active) {
		if (page_base == ctx->addr) {
			pr_debug("secondary hit for 0x%08lx CPU %d.\n", addr,
				 smp_processor_id());

			if (!faultpage->old_presence)
				pr_info("unexpected secondary hit for address 0x%08lx on CPU %d.\n",
					addr, smp_processor_id());
		} else {
			pr_emerg(
				"recursive probe hit on CPU %d, for address 0x%08lx. Ignoring.\n",
				smp_processor_id(), addr);
			pr_emerg("previous hit was at 0x%08lx.\n", ctx->addr);
			disarm_khwio_fault_page(faultpage);
		}
		goto no_khwio_ctx;
	}
	ctx->active++;

	ctx->fpage[0] = faultpage;
	ctx->fpage[1] = NULL;
	ctx->probe = get_khwio_probe(addr);
	ctx->addr = page_base;

	/* Now we set present bit in PTE. */
	disarm_khwio_fault_page(faultpage);

	/* For the cases where a memory access spans two pages */
	if (page_base + PAGE_SIZE - addr < 64) {
		faultpage = get_khwio_fault_page(page_base + PAGE_SIZE);
		if (faultpage) {
			disarm_khwio_fault_page(faultpage);
			ctx->fpage[1] = faultpage;
		}
	}

	if (ctx->probe) {
		ctx->decoded =
			arm64_decode(*(uint32_t *)instruction_pointer(regs),
				     &ctx->instr) == 0 ?
				true :
				false;

		if (ctx->decoded) {
#if ENABLE_HWIOTRACE_HANDLERS
			// TODO: check for probe mode
			if (ctx->probe->pre_handler) {
				ctx->probe->pre_handler(ctx->probe, regs, addr,
							&ctx->instr);
			}
#endif

			if (execute_hooks(ctx->probe, &ctx->instr, regs, addr,
					  (char *)page_base,
					  (char *)page_base + PAGE_SIZE) ==
			    SKIP_SINGLE_STEP) {
				unsigned long new_pc =
					instruction_pointer(regs) + 4;

				pr_info("khwio_handler emu %s [<0x%lx>] %s addr=0x%lx\n",
					ctx->instr.ld ? "ld" : "st",
					instruction_pointer(regs), symbuf,
					addr);

				post_khwio_handler(0, regs);
				regs->pc = new_pc;
				//preempt_enable_no_resched();
				put_cpu_var(khwio_ctx);
				local_irq_enable();
				return 1;
			}
		}
	}

	pr_info("khwio_handler %s [<0x%lx>] %s addr=0x%lx\n",
		ctx->instr.ld ? "ld" : "?", instruction_pointer(regs), symbuf,
		addr);

	put_cpu_var(khwio_ctx);

	kd.addr = (khwio_opcode_t *)instruction_pointer(regs);

#if SINGLE_STEP_ORIG_INSTR
	kd.ainsn.insn = (void *)regs->pc;
	kd.ainsn.restore =
		(unsigned long)kd.ainsn.insn + sizeof(khwio_opcode_t);
#else
	ret = arch_prepare_hwio_probe(
		&kd, (khwio_opcode_t *)khwio_insn_page); // Must be stateless
	//pr_info("khwio_handler addr=%p opcode=0x%x *addr=0x%x\n", kd.addr, kd.opcode, *kd.addr);

	//patch_text(kd.addr, BRK64_OPCODE_HWIO_PROBES);
#endif

	memcpy(&fault_regs, regs, sizeof(struct pt_regs));

	asm volatile("brk %0" : : "I"(BRK64_ESR_HWIO_PROBES));

	memcpy(regs, &fault_regs, sizeof(struct pt_regs));

	//spin_unlock_irqrestore(&khwio_lock, flags);
	//preempt_enable_no_resched();
	local_irq_restore(flags);
	return 1; /* fault handled */

no_khwio_ctx:
	put_cpu_var(khwio_ctx);
no_khwio:
#if DELAYED_RELEASE
	rcu_read_unlock();
#endif
	//spin_unlock_irqrestore(&khwio_lock, flags);
	//preempt_enable_no_resched();
	local_irq_restore(flags);
	return ret;
}

/* You must be holding khwio_lock. */
#if ADD_FAULT_PAGE
static int add_khwio_fault_page(unsigned long addr)
{
	struct khwio_fault_page *f;
	unsigned long flags = GFP_KERNEL;

	addr &= PAGE_MASK;

	f = get_khwio_fault_page(addr);
	if (f) {
		if (!f->count)
			arm_khwio_fault_page(f);
		f->count++;
		pr_info("add_khwio_fault_page f->addr=0x%lx f->count=%u\n",
			f->addr, f->count);
		return 0;
	}

	if (in_interrupt() || irqs_disabled() || in_atomic())
		flags = GFP_ATOMIC;

	f = kzalloc(sizeof(*f), flags);
	if (!f) {
		pr_err("add_khwio_fault_page failed to allocate khwio_fault_page\n");
		return -1;
	}

	f->count = 1;
	f->addr = addr;

	pr_info("add_khwio_fault_page f->addr=0x%lx f->count=%u\n", f->addr,
		f->count);

	if (arm_khwio_fault_page(f)) {
		pr_err("add_khwio_fault_page failed to arm page\n");
		kfree(f);
		return -1;
	}

	f->mapped_ptr = (unsigned long long *)f->addr;

#if !DELAYED_RELEASE
	list_add(&f->list, khwio_page_list(f->addr));
#else
	list_add_rcu(&f->list, khwio_page_list(f->addr));
#endif

	return 0;
}
#endif

/* You must be holding khwio_lock. */
static void release_khwio_fault_page(unsigned long addr,
				     struct khwio_fault_page **release_list)
{
	struct khwio_fault_page *f;

	addr = addr & PAGE_MASK;

	f = get_khwio_fault_page(addr);
	if (!f)
		return;

	pr_info("release_khwio_fault_page f->addr=0x%lx f->count=%u\n", f->addr,
		f->count);

	f->count--;
	BUG_ON(f->count < 0);
	if (!f->count) {
		disarm_khwio_fault_page(f);
		if (!f->scheduled_for_release) {
			f->release_next = *release_list;
			*release_list = f;
			f->scheduled_for_release = true;
		}
	}
}

int register_khwio_probe(struct khwio_probe *p)
{
	unsigned long flags;
	int ret = 0;
	unsigned long size = 0;
	const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
	unsigned int level;
	pte_t *pte;

	spin_lock_irqsave(&khwio_lock, flags);
	if (get_khwio_probe(p->addr)) {
		pr_err("register_khwio_probe already exists for addr=0x%lx\n",
		       p->addr);
		BUG(); // FIXME
		ret = -EEXIST;
		goto out;
	}

	pte = lookup_address(p->addr, &level);
	if (!pte) {
		pr_info("register_khwio_probe addr=0x%lx pte=null\n", p->addr);
		ret = -EINVAL;
		goto out;
	}

	khwio_count++;
	pr_info("register_khwio_probe khwio_count=%u addr=0x%lx size=%lu pte=0x%llx\n",
		khwio_count, p->addr, p->len, pte_val(*pte));

#if ADD_PROBES
	list_add(&p->list, &khwio_probes);
#endif
#if ADD_FAULT_PAGE
	while (size < size_lim) {
		if (add_khwio_fault_page(p->addr + size))
			pr_err("Unable to set page fault.\n");
		size += PAGE_SIZE;
	}
#endif

#if 0
#ifdef CONFIG_HWIOFUZZ
	if (kfuz_hwiotrace_init()) {
#ifdef CONFIG_KCOV
		kcov_hwiotrace_init();
#endif
	}
#endif
#endif
out:
	spin_unlock_irqrestore(&khwio_lock, flags);
	/*
	 * XXX: What should I do here?
	 * Here was a call to global_flush_tlb(), but it does not exist
	 * anymore. It seems it's not needed after all.
	 */
	return ret;
}
EXPORT_SYMBOL(register_khwio_probe);

#if DELAYED_RELEASE
static void rcu_free_khwio_fault_pages(struct rcu_head *head)
{
	struct khwio_delayed_release *dr =
		container_of(head, struct khwio_delayed_release, rcu);
	struct khwio_fault_page *f = dr->release_list;
	while (f) {
		struct khwio_fault_page *next = f->release_next;
		BUG_ON(f->count);
		kfree(f);
		f = next;
	}
	kfree(dr);
}

static void remove_khwio_fault_pages(struct rcu_head *head)
{
	struct khwio_delayed_release *dr =
		container_of(head, struct khwio_delayed_release, rcu);
	struct khwio_fault_page *f = dr->release_list;
	struct khwio_fault_page **prevp = &dr->release_list;
	unsigned long flags;

	spin_lock_irqsave(&khwio_lock, flags);
	while (f) {
		if (!f->count) {
			list_del_rcu(&f->list);
			prevp = &f->release_next;
		} else {
			*prevp = f->release_next;
			f->release_next = NULL;
			f->scheduled_for_release = false;
		}
		f = *prevp;
	}
	spin_unlock_irqrestore(&khwio_lock, flags);

	/* This is the real RCU destroy call. */
	call_rcu(&dr->rcu, rcu_free_khwio_fault_pages);
}
#else /* DELAYED_RELEASE */
static void remove_khwio_fault_pages(struct khwio_fault_page *release_list)
{
	struct khwio_fault_page *f = release_list;
	struct khwio_fault_page **prevp = &release_list;
	struct khwio_fault_page *prev = NULL;
	unsigned long flags;

	spin_lock_irqsave(&khwio_lock, flags);
	while (f) {
		if (!f->count) {
			list_del(&f->list);
			prevp = &f->release_next;
			prev = f->release_next;
			pr_info("remove_khwio_fault_pages f->addr=0x%lx *prevp=%p\n",
				f->addr, *prevp);
			kfree(f);
			f = prev;
		} else {
			pr_err("remove_khwio_fault_pages f->addr=0x%lx FATAL ERROR\n",
			       f->addr);
			*prevp = f->release_next;
			f->release_next = NULL;
			f->scheduled_for_release = false;
			f = *prevp;
		}
	}
	spin_unlock_irqrestore(&khwio_lock, flags);
}
#endif /* DELAYED_RELEASE */

void unregister_khwio_probe(struct khwio_probe *p)
{
	unsigned long flags;
	unsigned long size = 0;
	const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
	struct khwio_fault_page *release_list = NULL;
#if DELAYED_RELEASE
	struct khwio_delayed_release *drelease;
#endif
	unsigned int level;
	pte_t *pte;

	pte = lookup_address(p->addr, &level);
	if (!pte) {
		return;
	}
#if UNREGISTER_DISABLED
	return;
#endif
	if (!p) {
		pr_err("unregister_khwio_probe p=NULL\n");
		return;
	}

#if 0
#ifdef CONFIG_HWIOFUZZ
	if (kfuz_hwiotrace_exit()) {
#ifdef CONFIG_KCOV
		kcov_hwiotrace_exit();
#endif
	}
#endif
#endif

	spin_lock_irqsave(&khwio_lock, flags);
	while (size < size_lim) {
		release_khwio_fault_page(p->addr + size, &release_list);
		size += PAGE_SIZE;
	}

#if ADD_PROBES
#if !DELAYED_RELEASE
	list_del(&p->list);
#else
	list_del_rcu(&p->list);
#endif
#endif
	khwio_count--;
	spin_unlock_irqrestore(&khwio_lock, flags);

	if (!release_list) {
		pr_err("unregister_khwio_probe release_list not found for p->addr=0x%lx\n",
		       p->addr);
		return;
	}

	pr_info("unregister_khwio_probe khwio_count=%u p->addr=0x%lx\n",
		khwio_count, p->addr);

#if DELAYED_RELEASE
#if ATOMIC_KMALLOC
	drelease = kmalloc(sizeof(*drelease), GFP_ATOMIC);
#else
	drelease = kmalloc(sizeof(*drelease), GFP_KERNEL);
#endif
	if (!drelease) {
		pr_crit("leaking khwio_fault_page objects.\n");
		goto out;
	}
	drelease->release_list = release_list;

	call_rcu(&drelease->rcu, remove_khwio_fault_pages);
#else /* DELAYED_RELEASE */
	remove_khwio_fault_pages(release_list);
#endif /* DELAYED_RELEASE */
}
EXPORT_SYMBOL(unregister_khwio_probe);

#define TRACE_BREAKPOINT_HANDLER 0

int khwio_breakpoint_handler(struct pt_regs *regs, unsigned int esr)
{
#if TRACE_BREAKPOINT_HANDLER
	pr_info("khwio_breakpoint_handler entered\n");
#endif
	//patch_text(kd.addr, kd.opcode);
	regs->pc = instruction_pointer(regs) + 4;

	memcpy(&khwio_regs, regs, sizeof(struct pt_regs));
	memcpy(regs, &fault_regs, sizeof(struct pt_regs));

	if (kd.ainsn.insn) {
		/* prepare for single stepping */
		WARN_ON(regs->pstate & PSR_D_BIT);

		/* IRQs and single stepping do not mix well. */
		khwio_saved_irqflag = regs->pstate;
		regs->pstate |= PSR_I_BIT;
#if TRACE_BREAKPOINT_HANDLER
		pr_info("khwio_breakpoint_handler ainsn.insn=0x%llx ainsn.restore=0x%llx *ainsn.insn=%x\n",
			kd.ainsn.insn, kd.ainsn.restore, *kd.ainsn.insn);
#endif
		kernel_enable_single_step(regs);
#if SINGLE_STEP_ORIG_INSTR
		kd.ainsn.insn = (void *)regs->pc;
		kd.ainsn.restore =
			(unsigned long)kd.ainsn.insn + sizeof(khwio_opcode_t);
#endif
		regs->pc = (unsigned long)kd.ainsn.insn;
	}
#if 0
	else if (kd.ainsn.handler) {
		pr_info("khwio_handler simulation\n");

		/* insn simulation */
		kd.ainsn.handler((u32)kd.opcode, (long)kd.addr, regs);

		/* single step simulated, now go for post processing */
		post_khwio_handler(0, regs);
	}
#endif
	else {
		pr_warning("khwio_breakpoint_handler unreachable\n");
	}

#if TRACE_BREAKPOINT_HANDLER
	pr_info("khwio_breakpoint_handler exiting\n");
#endif

	return DBG_HOOK_HANDLED;
}

int khwio_single_step_handler(struct pt_regs *regs, unsigned int esr)
{
	unsigned long match_addr =
		(unsigned long)kd.ainsn.insn + sizeof(khwio_opcode_t);

	//pr_info("khwio_single_step_handler match_addr=0x%lx pc=0x%lx\n", match_addr, instruction_pointer(regs));

	BUG_ON(match_addr !=
	       instruction_pointer(regs)); // FIXME - this is for debugging

	if (match_addr != instruction_pointer(regs))
		return DBG_HOOK_ERROR;

	//dump_stack();

	if (khwio_saved_irqflag & PSR_I_BIT)
		regs->pstate |= PSR_I_BIT;
	else
		regs->pstate &= ~PSR_I_BIT;

	kernel_disable_single_step();

	if (post_khwio_handler(0, regs) != 0) {
		return DBG_HOOK_ERROR;
	}

	memcpy(&fault_regs, regs, sizeof(struct pt_regs));
	memcpy(regs, &khwio_regs, sizeof(struct pt_regs));

	return DBG_HOOK_HANDLED;
}

int khwio_init(void)
{
	int i;

	for (i = 0; i < KHWIO_PAGE_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&khwio_page_table[i]);

	targeted_fn_addr = 0UL;

#if !SINGLE_STEP_ORIG_INSTR
	khwio_insn_page = module_alloc(PAGE_SIZE);
#endif

	return 0;
}

void khwio_cleanup(void)
{
	int i;

	for (i = 0; i < KHWIO_PAGE_TABLE_SIZE; i++) {
		WARN_ONCE(
			!list_empty(&khwio_page_table[i]), KERN_ERR
			"khwio_page_table not empty at cleanup, any further tracing will leak memory.\n");
	}

#if !SINGLE_STEP_ORIG_INSTR
	module_memfree(khwio_insn_page);
#endif
}
