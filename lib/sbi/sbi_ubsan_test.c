/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Author: Marcos Oduardo <marcos.oduardo@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UBSAN_TESTS_ENABLED
#include <sbi/sbi_types.h>
#include <sbi/sbi_console.h>

void sbi_ubsan_test_suite(void)
{
    sbi_printf("\n[UBSan Test] Starting NetBSD-based test suite\n");

    {
        sbi_printf("\n[UBSan Test] Add Overflow Test\n");
        volatile int a = 0x7FFFFFFF;
        (void)a;
        volatile int b = 1;
        (void)b;
        volatile int c = a + b;
        (void)c;
    }

    {
        sbi_printf("\n[UBSan Test] Sub Overflow Test\n");
        volatile int a = 0x80000000;
        (void)a;
        volatile int b = 1;
        (void)b;
        volatile int c = a - b;
        (void)c;
    }

    {
        sbi_printf("\n[UBSan Test] Mul Overflow Test\n");
        volatile int a = 0x7FFFFFFF;
        (void)a;
        volatile int b = 2;
        (void)b;
        volatile int c = a * b;
        (void)c;
    }

    {
        sbi_printf("\n[UBSan Test] Div/Rem Overflow Test\n");
        volatile int a = 10;
        (void)a;
        volatile int b = 0;
        (void)b;
        volatile int c = a / b;
        (void)c;
    }

    {
        sbi_printf("\n[UBSan Test] Index Out of Bounds Test\n");
        volatile int idx = 5;
        (void)idx;
        int arr[3] = {1, 2, 3};
        volatile int val = arr[idx];
        (void)val;
    }

    {
        sbi_printf("\n[UBSan Test] Shift Exponent Too Large Test\n");
        volatile unsigned long val = 1;
        (void)val;
        volatile int shift = 64;
        (void)shift;
        volatile unsigned long res = val << shift;
        (void)res;
    }

    {
        sbi_printf("\n[UBSan Test] Shift Exponent Negative Test\n");
        volatile int val = 1;
        (void)val;
        volatile int shift = -1;
        (void)shift;
        volatile int res = val << shift;
        (void)res;
    }

    {
        sbi_printf("\n[UBSan Test] Misaligned Access Test\n");
        char buffer[16] __attribute__((aligned(16)));
        volatile int *ptr = (int *)&buffer[1];
        (void)ptr;
        volatile int val = *ptr;
        (void)val;
    }

    {
        sbi_printf("\n[UBSan Test] Null Dereference Test\n");
        volatile int *ptr = NULL;
        (void)ptr;
        sbi_printf("\n[UBSan Test] Uncomment next two lines of code for testing Null dereference\n");

        //volatile int val = *ptr;
        //(void)val;
    }

    {
        sbi_printf("\n[UBSan Test] Load Invalid Value Test\n");
        volatile char bool_val = 5;
        (void)bool_val;
        volatile bool *b_ptr = (bool *)&bool_val;
        (void)b_ptr;
        if (*b_ptr) { (void)0; }
    }

    {
        sbi_printf("\n[UBSan Test] Pointer Overflow Test\n");
        volatile uintptr_t base = 0xFFFFFFFFFFFFFFFEUL;
        (void)base;
        volatile char *ptr = (char *)base;
        (void)ptr;
        volatile char *res = ptr + 5;
        (void)res;
    }

    sbi_printf("\n[UBSan Test] All tests dispatched successfully.\n\n");
}
#endif