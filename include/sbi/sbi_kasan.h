/* 
 * SPDX-License-Identifier: BSD-2-Clause
 * Author: Marcos Oduardo <marcos.oduardo@gmail.com>
 */

#ifndef __SBI_KASAN_H__
#define __SBI_KASAN_H__

#include <sbi/sbi_list.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_domain.h>

struct heap_node;
struct sbi_heap_control;
struct sbi_domain_memregion;


void kasan_hart_init(struct sbi_scratch *scratch);
void kasan_init(struct sbi_scratch *scratch);
void *kasan_malloc_hook(struct sbi_heap_control *hpctrl, size_t size); 
void kasan_free_hook(struct sbi_heap_control *hpctrl, void *ptr);
void kasan_shadow_check(unsigned long addr, size_t size, bool write, unsigned long retaddr);
void sbi_kasan_get_shadow_region(struct sbi_domain_memregion *reg);
unsigned long sbi_kasan_get_shadow_size(void);

#endif
