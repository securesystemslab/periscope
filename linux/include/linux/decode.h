#ifndef SIMPLE_DECODE_H
#define SIMPLE_DECODE_H

#ifndef __KERNEL__
#include "linux_types.h"
#include <linux/types.h>
#else
#include <asm/ptrace.h>
#endif

struct Insn {
	unsigned int rt;
	int rt2;
	int rs;
	unsigned int rn;
	unsigned int rm;
	int of;
	unsigned short ld;
	unsigned short p;
	unsigned int len;
	unsigned int bin;
	bool sign_extend;
	bool wback;
	bool cache_op;
	// this holds the transferred value
	// for extended trace log output
	// and (potentially) seed generation
	long long transfer_val[2];
};

typedef int (*fp_decode)(uint32_t, struct Insn *);

struct opc {
	uint32_t mask;
	uint32_t val;
	fp_decode fp;
};

int arm64_decode(uint32_t insn, struct Insn *instr);
long long sd_field(unsigned long long insn, unsigned int start,
		   unsigned int len);
long long sd_mod_field(unsigned long long orig_val, unsigned long long new_val,
		       unsigned int start, unsigned int len);
int emulate_ld(struct Insn *instr, struct pt_regs *regs, char *data_ptr_c,
	       char *data_ptr_c2);
int emulate_st(struct Insn *instr, struct pt_regs *regs, char *data_ptr_c,
	       char *data_ptr_c2);
#endif
