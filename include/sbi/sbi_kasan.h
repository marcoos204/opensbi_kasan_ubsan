/* 
 * SPDX-License-Identifier: BSD-2-Clause
 * Author: Marcos Oduardo <marcos.oduardo@gmail.com>
 */

 #ifndef __SBI_KASAN_H__
#define __SBI_KASAN_H__

#include <sbi/sbi_list.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_scratch.h>

struct heap_node;
struct sbi_heap_control;



void kasan_init(struct sbi_scratch *scratch);
void *kasan_malloc_hook(struct sbi_heap_control *hpctrl, size_t size); 
void kasan_free_hook(struct sbi_heap_control *hpctrl, void *ptr);
void kasan_shadow_check(unsigned long addr, size_t size, bool write, unsigned long retaddr);

#endif
