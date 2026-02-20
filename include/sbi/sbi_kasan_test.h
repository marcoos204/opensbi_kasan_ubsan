/* 
 * SPDX-License-Identifier: BSD-2-Clause
 * Author: Marcos Oduardo <marcos.oduardo@gmail.com>
 */

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
void heap_kasan_test(void);
void stack_kasan_test(void);
void globals_kasan_test(void);
void memset_kasan_test(void);
void memcpy_kasan_test(void);
#endif
#endif