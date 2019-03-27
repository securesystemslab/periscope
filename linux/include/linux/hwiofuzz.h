#ifndef _LINUX_HWIOFUZZ_H
#define _LINUX_HWIOFUZZ_H

#ifdef CONFIG_HWIOFUZZ

extern bool kfuz_hwiotrace_init(void);
extern bool kfuz_hwiotrace_exit(void);
extern bool kfuz_hwiotrace_consume(void *dest, unsigned long base, int offset,
				   unsigned long len, bool cacheable);
extern bool kfuz_hwiotrace_mask(unsigned long base, int offset,
				unsigned long len);

#else

static inline bool kfuz_hwiotrace_init()
{
	return false;
}
static inline bool kfuz_hwiotrace_exit()
{
	return false;
}
extern inline bool kfuz_hwiotrace_consume(void *dest, unsigned long base,
					  int offset, unsigned long len,
					  bool cacheable)
{
	return false;
}
extern inline bool kfuz_hwiotrace_mask(unsigned long base, int offset,
				       unsigned long len)
{
	return false;
}

#endif /* CONFIG_HWIOFUZZ */

#endif /* _LINUX_HWIOFUZZ_H */
