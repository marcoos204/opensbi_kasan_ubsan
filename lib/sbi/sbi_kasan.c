
/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2018-2020 Maxime Villard, m00nbsd.net
 *
 * Author: Marcos Oduardo <marcos.oduardo@gmail.com>
 *               
 * All rights reserved.
 *
 * This code is part of the KASAN subsystem of the NetBSD kernel.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sbi/sbi_kasan.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_scratch.h>

#ifdef KASAN_ENABLED

#define __RET_ADDR ((unsigned long) __builtin_return_address(0))

/* ASAN constants. Part of the compiler ABI. */
#define KASAN_SHADOW_SCALE_SHIFT    3
#define KASAN_SHADOW_SCALE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK           (KASAN_SHADOW_SCALE_SIZE - 1)

// Poison Values
#define KASAN_GENERIC_REDZONE   0xFA
#define KASAN_MALLOC_REDZONE    0xFB
#define KASAN_HEAP_FREE         0xFD
#define KASAN_STACK_LEFT        0xF1
#define KASAN_STACK_MID         0xF2
#define KASAN_STACK_RIGHT       0xF3
#define KASAN_SHADOW_RESERVED   0xFF

#define KASAN_HEAD_SIZE         32
#define KASAN_TAIL_SIZE         32

// BSD Macros
#define roundup(x, y)           ((((x) + ((y) - 1)) / (y)) * (y))
#define __predict_true(x)       __builtin_expect((x) != 0, 1)
#define __predict_false(x)      __builtin_expect((x) != 0, 0)

#define KASAN_MEM_TO_SHADOW(addr) \
  (((addr) >> KASAN_SHADOW_SCALE_SHIFT) + __asan_shadow_memory_dynamic_address)

static bool kasan_enabled = false;
static unsigned long kasan_fw_base;
static unsigned long kasan_rw_offset;
static unsigned long kasan_fw_size;
unsigned long __asan_shadow_memory_dynamic_address; //shadow offset
static unsigned long kasan_shadow_size;
static unsigned long kasan_fw_start; //fw base + offset
static unsigned long kasan_fw_end; //fw base + size

#define ADDR_CROSSES_SCALE_BOUNDARY(addr, size) \
    ((addr >> KASAN_SHADOW_SCALE_SHIFT) != ((addr + size - 1) >> KASAN_SHADOW_SCALE_SHIFT))

__attribute__((no_sanitize("address")))
static inline int8_t *kasan_md_addr_to_shad(const void *addr) {
    return (int8_t *)(((unsigned long)(addr) >> KASAN_SHADOW_SCALE_SHIFT) + __asan_shadow_memory_dynamic_address);
}

__attribute__((no_sanitize("address")))
static inline bool kasan_md_illegal(unsigned long addr, bool is_write) {
    if (addr >= KASAN_SHADOW_MEMORY_START && addr < (KASAN_SHADOW_MEMORY_START + kasan_shadow_size)) 
    return true;

    if (addr >= kasan_fw_base && addr < kasan_fw_start){
        if (is_write) {
            return true;
        }
    }
    
    return false;

}


__attribute__((no_sanitize("address")))
static inline bool kasan_md_unsupported(unsigned long addr) {
    if (addr > kasan_fw_end) return true;
    
    if (addr < kasan_fw_base) return true;

    return false;
}


__attribute__((no_sanitize("address")))
static inline const char *kasan_code_name(uint8_t code) {
    switch (code) {
    case KASAN_GENERIC_REDZONE: return "GenericRedZone";
    case KASAN_MALLOC_REDZONE:  return "MallocRedZone";
    case KASAN_HEAP_FREE:       return "UseAfterFree";
    case 1 ... 7:               return "RedZonePartial";
    case KASAN_STACK_LEFT:      return "StackLeft";
    case KASAN_STACK_MID:       return "StackMiddle";
    case KASAN_STACK_RIGHT:     return "StackRight";
    default:                    return "Unknown";
    }
}

__attribute__((no_sanitize("address")))
static void kasan_report(unsigned long addr, size_t size, bool write, unsigned long pc, uint8_t code) {
    bool was_enabled = kasan_enabled;
    kasan_enabled = false;

    sbi_printf("\n");
    sbi_printf("ASan: Unauthorized Access In %p: Addr %p [%lu byte%s, %s, %s]\n",
        (void *)pc, (void *)addr, (unsigned long)size, (size > 1 ? "s" : ""),
        (write ? "write" : "read"), kasan_code_name(code));
        
    kasan_enabled = was_enabled;
}


__attribute__((no_sanitize("address")))
static inline bool kasan_shadow_1byte_isvalid(unsigned long addr, uint8_t *code) {
    int8_t *byte = kasan_md_addr_to_shad((void *)addr);
    int8_t last = (int8_t)((addr & KASAN_SHADOW_MASK) + 1);

    if (__predict_true(*byte == 0 || last <= *byte)) {
        return true;
    }
    *code = (uint8_t)*byte;
    return false;
}

__attribute__((no_sanitize("address")))
static inline bool kasan_shadow_2byte_isvalid(unsigned long addr, uint8_t *code) {
    if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 2)) {
        return (kasan_shadow_1byte_isvalid(addr, code) && 
                kasan_shadow_1byte_isvalid(addr+1, code));
    }
    int8_t *byte = kasan_md_addr_to_shad((void *)addr);
    int8_t last = (int8_t)(((addr + 1) & KASAN_SHADOW_MASK) + 1);

    if (__predict_true(*byte == 0 || last <= *byte)) {
        return true;
    }
    *code = (uint8_t)*byte;
    return false;
}

__attribute__((no_sanitize("address")))
static inline bool kasan_shadow_4byte_isvalid(unsigned long addr, uint8_t *code) {
    if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 4)) {
        return (kasan_shadow_2byte_isvalid(addr, code) && 
                kasan_shadow_2byte_isvalid(addr+2, code));
    }
    int8_t *byte = kasan_md_addr_to_shad((void *)addr);
    int8_t last = (int8_t)(((addr + 3) & KASAN_SHADOW_MASK) + 1);

    if (__predict_true(*byte == 0 || last <= *byte)) {
        return true;
    }
    *code = (uint8_t)*byte;
    return false;
}

__attribute__((no_sanitize("address")))
static inline bool kasan_shadow_8byte_isvalid(unsigned long addr, uint8_t *code) {
    if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 8)) {
        return (kasan_shadow_4byte_isvalid(addr, code) && 
                kasan_shadow_4byte_isvalid(addr+4, code));
    }
    int8_t *byte = kasan_md_addr_to_shad((void *)addr);
    int8_t last = (int8_t)(((addr + 7) & KASAN_SHADOW_MASK) + 1);

    if (__predict_true(*byte == 0 || last <= *byte)) {
        return true;
    }
    *code = (uint8_t)*byte;
    return false;
}

__attribute__((no_sanitize("address")))
static inline bool kasan_shadow_Nbyte_isvalid(unsigned long addr, size_t size, uint8_t *code) {
    size_t i;
    for (i = 0; i < size; i++) {
        if (!kasan_shadow_1byte_isvalid(addr+i, code)) return false;
    }
    return true;
}

__attribute__((no_sanitize("address")))
void kasan_shadow_check(unsigned long addr, size_t size, bool write, unsigned long retaddr) {
    uint8_t code = 0;
    bool valid = true;

    if (__predict_false(!kasan_enabled)) return;
    if (__predict_false(size == 0)) return;
    if (__predict_false(kasan_md_illegal(addr, write))) {
        kasan_report(addr, size, write, retaddr, KASAN_SHADOW_RESERVED);
        return;
    }
    if (__predict_false(kasan_md_unsupported(addr))) return;



    if (__builtin_constant_p(size)) {
        switch (size) {
        case 1: valid = kasan_shadow_1byte_isvalid(addr, &code); break;
        case 2: valid = kasan_shadow_2byte_isvalid(addr, &code); break;
        case 4: valid = kasan_shadow_4byte_isvalid(addr, &code); break;
        case 8: valid = kasan_shadow_8byte_isvalid(addr, &code); break;
        default: valid = kasan_shadow_Nbyte_isvalid(addr, size, &code); break;
        }
    } else {
        valid = kasan_shadow_Nbyte_isvalid(addr, size, &code);
    }

    if (__predict_false(!valid)) {
        kasan_report(addr, size, write, retaddr, code);
    }
}

__attribute__((no_sanitize("address")))
static void kasan_shadow_Nbyte_fill(const void *addr, size_t size, uint8_t code)
{
    void *shad;

    if (__predict_false(size == 0)) return;
    if (__predict_false(kasan_md_unsupported((unsigned long)addr))) return;
    
    shad = (void *)kasan_md_addr_to_shad(addr);
    size = size >> KASAN_SHADOW_SCALE_SHIFT;

    _real_sbi_memset(shad, code, size);
}

__attribute__((no_sanitize("address")))
static __always_inline void
kasan_shadow_1byte_markvalid(unsigned long addr)
{
    int8_t *byte = kasan_md_addr_to_shad((void *)addr);
    int8_t last = (addr & KASAN_SHADOW_MASK) + 1;

    *byte = last;
}

__attribute__((no_sanitize("address")))
static __always_inline void
kasan_shadow_Nbyte_markvalid(const void *addr, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        kasan_shadow_1byte_markvalid((unsigned long)addr + i);
    }
}

/*
 * In an area of size 'sz_with_redz', mark the 'size' first bytes as valid,
 * and the rest as invalid. There are generally two use cases:
 *
 *  o kasan_mark(addr, origsize, size, code), with origsize < size. This marks
 *    the redzone at the end of the buffer as invalid.
 *
 *  o kasan_mark(addr, size, size, 0). This marks the entire buffer as valid.
 */

 __attribute__((no_sanitize("address")))
void kasan_mark(const void *addr, size_t size, size_t sz_with_redz, uint8_t code)
{
    size_t i, n, redz;
    int8_t *shad;

    if (kasan_md_unsupported((unsigned long)addr)) return;

    redz = sz_with_redz - roundup(size, KASAN_SHADOW_SCALE_SIZE);
    shad = kasan_md_addr_to_shad(addr);

    /* Chunks of 8 bytes, valid. */
    n = size / KASAN_SHADOW_SCALE_SIZE;
    for (i = 0; i < n; i++) {
        *shad++ = 0;
    }

    /* Possibly one chunk, mid. */
    if ((size & KASAN_SHADOW_MASK) != 0) {
        *shad++ = (size & KASAN_SHADOW_MASK);
    }
    
    /* Chunks of 8 bytes, invalid. */
    n = redz / KASAN_SHADOW_SCALE_SIZE;
    for (i = 0; i < n; i++) {
        *shad++ = code;
    }
}


__attribute__((no_sanitize("address")))
void kasan_md_init(struct sbi_scratch *scratch) 
{
    kasan_fw_base = scratch->fw_start;
    kasan_rw_offset = scratch->fw_rw_offset;
    kasan_fw_size = scratch->fw_size;
    kasan_fw_start = kasan_fw_base + kasan_rw_offset;
    kasan_fw_end = kasan_fw_base + kasan_fw_size;
    __asan_shadow_memory_dynamic_address = KASAN_SHADOW_MEMORY_START - (kasan_fw_start >> KASAN_SHADOW_SCALE_SHIFT);
    kasan_shadow_size = (kasan_fw_end - kasan_fw_start + 1) >> KASAN_SHADOW_SCALE_SHIFT;

    _real_sbi_memset((void*)KASAN_SHADOW_MEMORY_START, 0, kasan_shadow_size);
   
    kasan_enabled = true;
}

__attribute__((no_sanitize("address")))
void kasan_ctors(void)
{
    extern unsigned long __CTOR_LIST__, __CTOR_END__;
    size_t nentries, i;
    unsigned long *ptr;

    nentries = ((size_t)&__CTOR_END__ - (size_t)&__CTOR_LIST__) / sizeof(unsigned long);

    ptr = &__CTOR_LIST__;
    for (i = 0; i < nentries; i++) {
        void (*func)(void);
        func = (void *)(*ptr);
        (*func)();
        ptr++;
    }
}


#define DEFINE_ASAN_LOAD_STORE(size) \
    __attribute__((no_sanitize("address"))) void __asan_load##size(unsigned long addr) { \
        kasan_shadow_check(addr, size, false, __RET_ADDR); \
    } \
    __attribute__((no_sanitize("address"))) void __asan_load##size##_noabort(unsigned long addr) { \
        kasan_shadow_check(addr, size, false, __RET_ADDR); \
    } \
    __attribute__((no_sanitize("address"))) void __asan_store##size(unsigned long addr) { \
        kasan_shadow_check(addr, size, true, __RET_ADDR); \
    } \
    __attribute__((no_sanitize("address"))) void __asan_store##size##_noabort(unsigned long addr) { \
        kasan_shadow_check(addr, size, true, __RET_ADDR); \
    }

DEFINE_ASAN_LOAD_STORE(1)
DEFINE_ASAN_LOAD_STORE(2)
DEFINE_ASAN_LOAD_STORE(4)
DEFINE_ASAN_LOAD_STORE(8)
DEFINE_ASAN_LOAD_STORE(16)

__attribute__((no_sanitize("address"))) void __asan_loadN(unsigned long addr, size_t size) {
    kasan_shadow_check(addr, size, false, __RET_ADDR);
}
__attribute__((no_sanitize("address"))) void __asan_loadN_noabort(unsigned long addr, size_t size) {
    kasan_shadow_check(addr, size, false, __RET_ADDR);
}
__attribute__((no_sanitize("address"))) void __asan_storeN(unsigned long addr, size_t size) {
    kasan_shadow_check(addr, size, true, __RET_ADDR);
}
__attribute__((no_sanitize("address"))) void __asan_storeN_noabort(unsigned long addr, size_t size) {
    kasan_shadow_check(addr, size, true, __RET_ADDR);
}
__attribute__((no_sanitize("address"))) void __asan_handle_no_return(void) {}

// 8. GLOBALS

struct __asan_global {
    const void *beg;
    size_t size;
    size_t size_with_redzone;
    const void *name;
    const void *module_name;
    unsigned long has_dynamic_init;
    void *location;
    unsigned long odr_indicator;
};

__attribute__((no_sanitize("address")))
void __asan_register_globals(struct __asan_global *globals, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        kasan_mark(globals[i].beg, globals[i].size, 
                   globals[i].size_with_redzone, KASAN_GENERIC_REDZONE);
    }
}

__attribute__((no_sanitize("address"))) 
void __asan_unregister_globals(struct __asan_global *globals, size_t n) {
}


__attribute__((no_sanitize("address")))
void *kasan_malloc_hook(struct sbi_heap_control *hpctrl, size_t size) {
    size_t aligned_size;
    size_t total_size;
    size_t *size_ptr;
    void *ptr;
    void *user_ptr;

    if (size == 0)
        return NULL;

    aligned_size = roundup(size, KASAN_SHADOW_SCALE_SIZE);
    total_size = sizeof(size_t) + KASAN_HEAD_SIZE + aligned_size + KASAN_TAIL_SIZE;
    
    ptr = sbi_malloc_from(hpctrl, total_size);
    if (ptr == NULL)
        return NULL;

    size_ptr = (size_t *)ptr;
    *size_ptr = total_size;
    
    user_ptr = (uint8_t *)ptr + sizeof(size_t) + KASAN_HEAD_SIZE;
    
    kasan_shadow_Nbyte_fill(ptr, sizeof(size_t) + KASAN_HEAD_SIZE,
                            KASAN_MALLOC_REDZONE);
    
    kasan_mark(user_ptr, size, aligned_size + KASAN_TAIL_SIZE,
               KASAN_MALLOC_REDZONE);

    return user_ptr;
}

__attribute__((no_sanitize("address")))
void kasan_free_hook(struct sbi_heap_control *hpctrl, void *ptr) {
    void *real_ptr;
    size_t *size_ptr;
    size_t total_size;
    size_t poison_size;

    if (ptr == NULL)
        return;

    real_ptr = (uint8_t *)ptr - (sizeof(size_t) + KASAN_HEAD_SIZE);
    
    size_ptr = (size_t *)real_ptr;
    total_size = *size_ptr;
    
    sbi_free_from(hpctrl, real_ptr);
    
    poison_size = total_size - sizeof(size_t) - KASAN_HEAD_SIZE;
    kasan_shadow_Nbyte_fill(ptr, poison_size, KASAN_HEAP_FREE);
}


#define DEFINE_ASAN_SET_SHADOW(byte)                        \
  __attribute__((no_sanitize("address")))                   \
  void __asan_set_shadow_##byte(void *addr, size_t size) {  \
    _real_sbi_memset(addr, 0x##byte, size);                 \
  }

DEFINE_ASAN_SET_SHADOW(00)
DEFINE_ASAN_SET_SHADOW(f1)
DEFINE_ASAN_SET_SHADOW(f2)
DEFINE_ASAN_SET_SHADOW(f3)

__attribute__((no_sanitize("address")))
void __asan_poison_stack_memory(const void *addr, size_t size) {
    size = roundup(size, KASAN_SHADOW_SCALE_SIZE);
    kasan_shadow_Nbyte_fill(addr, size, KASAN_STACK_MID);
}

__attribute__((no_sanitize("address")))
void __asan_unpoison_stack_memory(const void *addr, size_t size) {
    kasan_shadow_Nbyte_markvalid(addr, size);
}

__attribute__((no_sanitize("address"))) 
void kasan_init(struct sbi_scratch *scratch) {
    kasan_md_init(scratch);
    kasan_ctors();
}

#endif
