/*
 * Copyright 2024 Google LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __SBI_KASAN_H__
#define __SBI_KASAN_H__

#include <sbi/sbi_list.h>
#include <sbi/riscv_locks.h>

struct heap_node;
struct sbi_heap_control;



void initialize_kasan(void);
void * __kasan_memcpy(void *dst, const void *src, size_t size,
                     unsigned long pc);
void * __kasan_memset(void *buf, int c, size_t size, unsigned long pc);
void *kasan_malloc_hook(struct sbi_heap_control *hpctrl, size_t size); 
void kasan_free_hook(struct sbi_heap_control *hpctrl, void *ptr);
extern char __global_ctors_start;
extern char __global_ctors_end;

void call_global_ctors(void);
#endif
