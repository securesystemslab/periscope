#ifndef SIMPLE_DECODE_HELPER_H
#define SIMPLE_DECODE_HELPER_H

#include <linux/types.h>

#define MAX_INSN_SIZE 1

typedef u32 khwio_opcode_t;

struct khwio_arch_specific_insn {
	khwio_opcode_t *insn;
	/* restore address after step xol */
	unsigned long restore;
};

struct khwio_decode_ctx {
	/* location of the probe point */
	khwio_opcode_t *addr;

	/* Offset into the symbol */
	unsigned int offset;

	/* Saved opcode (which has been replaced with breakpoint) */
	khwio_opcode_t opcode;

	struct khwio_arch_specific_insn ainsn;
};

enum khwio_insn {
	INSN_REJECTED,
	INSN_GOOD_NO_SLOT,
	INSN_GOOD,
};

#endif
