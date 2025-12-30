#ifndef __SBI_KASAN_TEST_H__
#define __SBI_KASAN_TEST_H__

#ifdef KASAN_TESTS_ENABLED

#include <sbi/sbi_kasan.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_heap.h>

typedef void (*global_ctor)(void);

// These symbols are defined in the linker script.
extern char __global_ctors_start;
extern char __global_ctors_end;

void call_global_ctors(void);
void test_heap_overflow(void);
void test_stack_overflow(void);
void test_globals_overflow(void);
void test_memset_overflow(void);
void test_memcpy_overflow(void);
#endif
#endif