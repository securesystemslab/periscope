#ifdef __KERNEL__
#include <linux/printk.h>
#include <linux/errno.h>
#include <asm/page.h>
#include <linux/decode.h>
#else
#include "decode.h"
#endif

static long long get_reg_val(struct pt_regs *regs, int reg_idx, bool *valid)
{
	*valid = false;
	if (reg_idx == 31) {
		*valid = true;
		return 0;
	} else if (reg_idx >= 0 && reg_idx < 31) {
		*valid = true;
		return regs->regs[reg_idx];
	}
	return -1;
}

// we need to use one byte copies
// otherwise we will get alignment faults because
// remapped mem is not "normal"
static void update_mem(long long reg_data, char *data_ptr_c, char *data_ptr_c2,
		       unsigned int len, char *transfer_val)
{
	size_t i;
	char *reg_data_ptr = (char *)&reg_data;
	unsigned int bytes_total = len;
	size_t transfer_val_idx = 0;
	if (unlikely(data_ptr_c2)) {
		unsigned int bytes_left =
			PAGE_SIZE - (((unsigned long)data_ptr_c) & 0xfff);
		if (unlikely(bytes_left <= bytes_total)) {
			pr_info("Splitting mem access %d = %d + %d\n",
				bytes_total, bytes_left,
				bytes_total - bytes_left);
			for (i = 0; i < bytes_left; ++i) {
				data_ptr_c[i] = reg_data_ptr[i];
				transfer_val[transfer_val_idx++] =
					reg_data_ptr[i];
			}
			for (i = 0; i < (bytes_total - bytes_left); ++i) {
				data_ptr_c2[i] = reg_data_ptr[bytes_left + i];
				transfer_val[transfer_val_idx++] =
					reg_data_ptr[bytes_left + i];
			}
			return;
		}
	}
	for (i = 0; i < bytes_total; ++i) {
		data_ptr_c[i] = reg_data_ptr[i];
		transfer_val[transfer_val_idx++] = reg_data_ptr[i];
	}
}

// Unused
#if 0
static void get_mem(long long* mem_data, char* data_ptr_c, char* data_ptr_c2, unsigned int len)
{
   size_t i;
   char* mem_data_ptr;
   unsigned int bytes_total;
   *mem_data = 0;
   mem_data_ptr = (char*)mem_data;
   bytes_total = len;
   if(unlikely(data_ptr_c2)) {
      unsigned int bytes_left = PAGE_SIZE - (((unsigned long)data_ptr_c) & 0xfff);
      if(unlikely(bytes_left <= bytes_total)) {
         pr_info("Splitting mem access %d = %d + %d\n",
               bytes_total, bytes_left, bytes_total - bytes_left);
         for(i = 0; i < bytes_left; ++i) {
            mem_data_ptr[i] = data_ptr_c[i];
         }
         for(i = 0; i < (bytes_total - bytes_left); ++i) {
            mem_data_ptr[bytes_left + i] = data_ptr_c2[i];
         }
         return;
      }
   }
   for(i = 0; i < bytes_total; ++i) {
      mem_data_ptr[i] = mem_data[i];
   }
}
#endif

int emulate_st(struct Insn *instr, struct pt_regs *regs, char *data_ptr_c,
	       char *data_ptr_c2)
{
	bool reg_valid = false;
	long long reg_data = get_reg_val(regs, instr->rt, &reg_valid);
	instr->transfer_val[0] = 0;
	instr->transfer_val[1] = 0;

	update_mem(reg_data, data_ptr_c, data_ptr_c2, instr->len,
		   (char *)instr->transfer_val);
	if (data_ptr_c2 == NULL) {
		pr_info("emulate_st (%d) reg[%d] %llx -> %llx\n", instr->len,
			instr->rt, reg_data, *(long long *)data_ptr_c);
	} else {
		pr_info("emulate_st (%d) reg[%d] %llx\n", instr->len, instr->rt,
			reg_data);
	}

	if (!reg_valid) {
		pr_err("emulate_st error getting register rt[%u] = %llx\n",
		       instr->rt, reg_data);
		return -EFAULT;
	}

	reg_data = get_reg_val(regs, instr->rt2, &reg_valid);
	if (reg_valid) {
		unsigned int bytes_total;
		unsigned int bytes_left;
		if (instr->len != 4 && instr->len != 8) {
			pr_err("emulate_st error invalid instruction length for stp %u\n",
			       instr->len);
			return -EFAULT;
		}

		bytes_total = instr->len;
		bytes_left = PAGE_SIZE - (((unsigned long)data_ptr_c) & 0xfff);
		if (unlikely(bytes_left <= bytes_total)) {
			pr_info("switching page on stp left %d, total %d\n",
				bytes_left, bytes_total);
			data_ptr_c = data_ptr_c2;
		} else {
			data_ptr_c += bytes_total;
		}

		update_mem(reg_data, data_ptr_c, NULL, instr->len,
			   (char *)instr->transfer_val);

		pr_info("emulate_st (%d) reg[%d] %llx -> %llx\n", instr->len,
			instr->rt2, regs->regs[instr->rt2],
			*(long long *)data_ptr_c);
		if (instr->wback) {
			regs->regs[instr->rn] =
				regs->regs[instr->rn] + instr->len;
		}
	}
	if (instr->rs >= 0) {
		regs->regs[instr->rs] = 1;
	}

	if (instr->wback) {
		regs->regs[instr->rn] = regs->regs[instr->rn] + instr->len;
	}

	return 0;
}

int update_reg(long long *reg_ptr_c, char *data_ptr_c, struct Insn *instr)
{
	//instr->sign_extend = true;
	switch (instr->len) {
	case 1:
		if (instr->sign_extend) {
			*reg_ptr_c = *(char *)data_ptr_c;
			instr->transfer_val[0] = *data_ptr_c;
		} else {
			*reg_ptr_c = *(unsigned char *)data_ptr_c;
			instr->transfer_val[0] = *data_ptr_c;
		}
		break;
	case 2:
		if (instr->sign_extend) {
			*reg_ptr_c = *(short *)data_ptr_c;
			instr->transfer_val[0] = *(short *)data_ptr_c;
		} else {
			*reg_ptr_c = *(unsigned short *)data_ptr_c;
			instr->transfer_val[0] = *(unsigned short *)data_ptr_c;
		}
		break;
	case 4:
		if (instr->sign_extend) {
			*reg_ptr_c = *(int *)data_ptr_c;
			instr->transfer_val[0] = *(int *)data_ptr_c;
		} else {
			*reg_ptr_c = *(unsigned int *)data_ptr_c;
			instr->transfer_val[0] = *(unsigned int *)data_ptr_c;
		}
		break;
	case 8:
		if (instr->sign_extend) {
			*reg_ptr_c = *(long long *)data_ptr_c;
			instr->transfer_val[0] = *(long long *)data_ptr_c;
		} else {
			*reg_ptr_c = *(unsigned long long *)data_ptr_c;
			instr->transfer_val[0] =
				*(unsigned long long *)data_ptr_c;
		}
		break;
	}
	return 0;
}

int emulate_ld(struct Insn *instr, struct pt_regs *regs, char *data_ptr_c,
	       char *data_ptr_c2)
{
	instr->transfer_val[0] = 0;
	instr->transfer_val[1] = 0;

	update_reg((long long *)&regs->regs[instr->rt], data_ptr_c, instr);
	if (data_ptr_c2 == NULL)
		pr_info("emulate_ld (%u) regs[%u] %llx <- %llx\n", instr->len,
			instr->rt, regs->regs[instr->rt],
			*(long long *)data_ptr_c);
	else
		pr_info("emulate_ld (%u) regs[%u] %llx\n", instr->len,
			instr->rt, regs->regs[instr->rt]);

	// handle ldp x1, x2, [mem]
	// ldp and stp only work on 32 or 64 bit
	if (instr->rt2 >= 0 && instr->rt2 < 31) {
		unsigned int bytes_total;
		unsigned int bytes_left;
		if (instr->len != 4 && instr->len != 8) {
			pr_err("emulate_ld error invalid instruction length for ldp %u\n",
			       instr->len);
			return -EFAULT;
		}

		// handle page boundary
		bytes_total = instr->len;
		bytes_left = PAGE_SIZE - (((unsigned long)data_ptr_c) & 0xfff);
		if (unlikely(bytes_left <= bytes_total)) {
			pr_info("switching page on stp left %d, total %d\n",
				bytes_left, bytes_total);
			data_ptr_c = data_ptr_c2;
		} else {
			data_ptr_c += bytes_total;
		}

		update_reg((long long *)&regs->regs[instr->rt2], data_ptr_c,
			   instr);

		if (instr->wback) {
			regs->regs[instr->rn] =
				regs->regs[instr->rn] + instr->len;
		}
	}

	if (instr->wback) {
		regs->regs[instr->rn] = regs->regs[instr->rn] + instr->len;
	}

	return 0;
}

long long sd_field(unsigned long long insn, unsigned int start,
		   unsigned int len)
{
	unsigned long long value;
	if (len == 64)
		return insn;
	value = insn >> start;
	return value & ~(-1ULL << len);
}

static int LdSt_P_Signed(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;

	if (size == 0) {
		out->len = 4;
		out->sign_extend = false;
	} else if (size == 2) {
		out->len = 8;
		out->sign_extend = false;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 30, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rt2 = sd_field(insn, 10, 5);
	out->rm = 0;
	out->of = sd_field(insn, 15, 7);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_P_UnSigned(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;
	if (size == 0) {
		out->len = 4;
		out->sign_extend = false;
	} else if (size == 2) {
		out->len = 8;
		out->sign_extend = false;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 30, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rt2 = sd_field(insn, 10, 5);
	out->rm = 0;
	out->of = sd_field(insn, 15, 7);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = true;
	return 0;
}

static int LdSt_B_Imm_Signed(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	long long owb;
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 1;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 12, 9);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;

	owb = sd_field(insn, 10, 2);
	if (owb == 0)
		out->wback = false;
	else
		out->wback = true;
	return 0;
}

static int LdSt_B_Imm_UnSigned(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 1;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 10, 12);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_B_Reg(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 1;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = sd_field(insn, 16, 5);
	out->of = 0;
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_H_Imm_Signed(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	long long owb;
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 2;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 12, 9);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;

	owb = sd_field(insn, 10, 2);
	if (owb == 0)
		out->wback = false;
	else
		out->wback = true;
	return 0;
}

static int LdSt_H_Imm_UnSigned(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 2;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 10, 12);
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_H_Reg(uint32_t insn, struct Insn *out)
{
	long long o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->len = 2;
	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = sd_field(insn, 16, 5);
	out->of = 0;
	out->ld = sd_field(insn, 22, 1);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_Imm_Signed(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;
	long long owb;
	if (size == 3) {
		out->len = 8;
	} else if (size == 2) {
		out->len = 4;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 12, 9);
	out->ld = sd_field(insn, 22, 1);
	out->p = sd_field(insn, 10, 1);

	owb = sd_field(insn, 10, 2);
	if (owb == 0)
		out->wback = false;
	else
		out->wback = true;

	return 0;
}

// b988d042
// 1011 1001 1000
// 1011 1000 100 //
static int LdSt_Imm_UnSigned(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;
	if (size == 3) {
		out->len = 8;
	} else if (size == 2) {
		out->len = 4;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
		out->ld = sd_field(insn, 22, 1);
	} else {
		out->sign_extend = true;
		out->ld = 1;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = sd_field(insn, 10, 11);
	out->p = 0;
	out->wback = false;
	return 0;
}

static int LdSt_Reg(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;
	if (size == 3) {
		out->len = 8;
	} else if (size == 2) {
		out->len = 4;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = sd_field(insn, 16, 5);
	out->of = sd_field(insn, 12, 9);
	out->ld = sd_field(insn, 22, 1);
	out->wback = false;
	return 0;
}

static int LdSt_Lit(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	if (size == 0) {
		out->len = 4;
		out->sign_extend = false;
	} else if (size == 1) {
		out->len = 8;
		out->sign_extend = false;
	} else if (size == 2) {
		out->len = 4;
		out->sign_extend = true;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rn = -1;
	out->rm = 0;
	out->of = sd_field(insn, 5, 19);
	out->ld = 0;
	out->wback = false;
	return 0;
}

static int LdSt_X_Reg(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	out->sign_extend = false;
	if (size == 2) {
		out->len = 4;
	} else if (size == 3) {
		out->len = 8;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rt2 = -1;
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = 0;
	out->ld = sd_field(insn, 22, 1);
	out->wback = false;
	return 0;
}

static int LdSt_SW_Reg(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	long long o;
	long long wb;
	out->sign_extend = false;
	if (size == 2) {
		out->len = 4;
	} else if (size == 3) {
		out->len = 8;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	o = sd_field(insn, 23, 1);
	if (o == 0) {
		out->sign_extend = false;
	} else {
		out->sign_extend = true;
	}

	wb = sd_field(insn, 24, 2);
	if (wb == 0)
		out->wback = true;
	else
		out->wback = false;

	out->rt = sd_field(insn, 0, 5);
	out->rt2 = -1;
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = 0;
	out->ld = sd_field(insn, 22, 1);
	return 0;
}

// 0 | 111 11 | 00 001 | 0 0010
static int LdSt_PX(uint32_t insn, struct Insn *out)
{
	long long size = sd_field(insn, 30, 2);
	out->sign_extend = false;
	out->wback = false;
	if (size == 2) {
		out->len = 4;
	} else if (size == 3) {
		out->len = 8;
	} else {
		pr_err("Error decoding %x\n", insn);
		return -EFAULT;
	}

	out->rt = sd_field(insn, 0, 5);
	out->rs = sd_field(insn, 16, 5);
	out->rn = sd_field(insn, 5, 5);
	out->rm = 0;
	out->of = 0;
	out->ld = sd_field(insn, 22, 1);
	return 0;
}

static int cache_op(uint32_t insn, struct Insn *out)
{
	out->cache_op = true;
	return 0;
}

unsigned int n_decs = 12;
struct opc decs[] = { {
			      // 1 x 1 1 | 1 0 0 0 0 1 0
			      // 1 x 1 1 | 1 0 0 1 0 1
			      .mask = 0xbf200000,
			      .val = 0xb8000000,
			      .fp = LdSt_Imm_Signed,
		      },
		      {
			      .mask = 0xbf000000,
			      .val = 0xb9000000,
			      .fp = LdSt_Imm_UnSigned,
		      },
		      {
			      .mask = 0xbf200000,
			      .val = 0xb8200000,
			      .fp = LdSt_Reg,
		      },
		      {
			      .mask = 0xbf000000,
			      .val = 0x18000000,
			      .fp = LdSt_Lit,
		      },
		      {
			      .mask = 0xff200000,
			      .val = 0x38200000,
			      .fp = LdSt_B_Reg,
		      },
		      {
			      .mask = 0xff200000,
			      .val = 0x38000000,
			      .fp = LdSt_B_Imm_Signed,
		      },
		      {
			      .mask = 0xff200000,
			      .val = 0x39000000,
			      .fp = LdSt_B_Imm_UnSigned,
		      },
		      {
			      .mask = 0xff200000,
			      .val = 0x78200000,
			      .fp = LdSt_H_Reg,
		      },
		      {
			      .mask = 0xff200000,
			      .val = 0x78000000,
			      .fp = LdSt_H_Imm_Signed,
		      },
		      {
			      .mask = 0xff000000,
			      .val = 0x79000000,
			      .fp = LdSt_H_Imm_UnSigned,
		      },
		      {
			      .mask = 0x7e800000,
			      .val = 0x28000000,
			      .fp = LdSt_P_Signed,
		      },
		      {
			      .mask = 0x7e800000,
			      .val = 0x28800000,
			      .fp = LdSt_P_UnSigned,
		      },
		      {
			      // 1 x 0 0 | 1 0 0 0 | 0 1 0
			      .mask = 0xbfe00000,
			      .val = 0x88400000,
			      .fp = LdSt_X_Reg,
		      },
		      {
			      // 1 0 1 1 | 1 0 0 x | 1 0
			      // 1 0 1 1 | 1 0 0 x | 1 0 0
			      .mask = 0xfec00000,
			      .val = 0xb8800000,
			      .fp = LdSt_SW_Reg,
		      },
		      {
			      // 1 x 0 0 | 1 0 0 0 | 0 0 0  S
			      // 1 x 0 0 | 1 0 0 0 | 0 1 0  L
			      .mask = 0xbfa00000,
			      .val = 0x88000000,
			      .fp = LdSt_PX,
		      },
		      {
			      // 1 1 0 1 | 0 1 0 1 | 0 0 0 0 | 1
			      .mask = 0xfff80000,
			      .val = 0xd5080000,
			      .fp = cache_op,
		      },
		      {
			      .mask = 0,
			      .val = 0,
			      .fp = NULL,
		      } };

struct opc data_cache_inv = {
	.mask = 0xfff9f000,
	.val = 0xd5087000,
};

int arm64_decode(uint32_t insn, struct Insn *instr)
{
	unsigned int i;

	if ((insn & data_cache_inv.mask) == data_cache_inv.val) {
		return -EINVAL;
	}
	instr->rt2 = -1;
	instr->wback = false;
	instr->cache_op = false;
	instr->rs = -1;
	for (i = 0; decs[i].mask != 0; ++i) {
		if ((insn & decs[i].mask) == decs[i].val) {
			//printf("----> %d\n", i);
			if (decs[i].fp(insn, instr) != 0) {
				return -EFAULT;
			}
			instr->bin = insn;
			return 0;
		}
	}
	return -EINVAL;
}
