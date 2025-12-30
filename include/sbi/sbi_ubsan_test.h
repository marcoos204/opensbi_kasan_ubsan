#ifndef __SBI_UBSAN_TEST_H__
#define __SBI_UBSAN_TEST_H__

#ifdef UBSAN_TESTS_ENABLED

#include <sbi/sbi_ubsan.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_heap.h>

void test_ubsan_add_overflow(void);
void test_ubsan_sub_overflow(void);
void test_ubsan_mul_overflow(void);
void test_ubsan_negate_overflow(void);
void test_ubsan_divrem_overflow(void);
void test_ubsan_truncate_signed(void);
void test_ubsan_shift_out_of_bounds(void);
void test_ubsan_out_of_bounds(void);

enum ubsan_test_enum {
	UBSAN_TEST_ZERO = 0,
	UBSAN_TEST_ONE,
	UBSAN_TEST_MAX,
};

void test_ubsan_load_invalid_value(void);
#endif
#endif