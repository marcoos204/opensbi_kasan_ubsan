#ifdef UBSAN_TESTS_ENABLED
#include <sbi/sbi_ubsan_test.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"


void test_ubsan_add_overflow(void)
{
	volatile int val = INT_MAX;
  sbi_printf("\nKUBSan test: integer overflow in add operation\n");
  sbi_printf("Overflowing integer variable with INT_MAX value\n");
  
	val += 2;
}

void test_ubsan_sub_overflow(void)
{
	volatile int val = INT_MIN;
	volatile int val2 = 2;

  sbi_printf("\nKUBSan test: integer underflow in sub operation\n");
  sbi_printf("Underflowing integer variable with INT_MIN value\n");

	val -= val2;

}

void test_ubsan_mul_overflow(void)
{
	volatile int val = INT_MAX / 2;

  
  sbi_printf("\nKUBSan test: integer overflow in mul operation\n");
  sbi_printf("Overflowing integer variable with INT_MAX value\n");

	val *= 3;
}

void test_ubsan_negate_overflow(void)
{
	volatile int val = INT_MIN;

  sbi_printf("\nKUBSan test: integer negate overflow\n");
  sbi_printf("Overflowing by negating integer variable with INT_MIN value\n");

	val = -val;
}

void test_ubsan_divrem_overflow(void)
{
	volatile int val = 16;
	volatile int val2 = 0;

  sbi_printf("\nKUBSan test: integer division by zero\n");
  sbi_printf("Dividing by zero variable with %d value\n", val);

	val /= val2;
}

void test_ubsan_truncate_signed(void)
{
	volatile long val = LONG_MAX;
	volatile int val2 = 0;

  sbi_printf("\nKUBSan test: signed variable truncation\n");
  sbi_printf("Truncating long variable with LONG_MAX value assigning its value to a int variable\n");

	val2 = val;

  
}

void test_ubsan_shift_out_of_bounds(void)
{
	volatile int neg = -1, wrap = 4;
	volatile int val1 = 10;
	volatile int val2 = INT_MAX;

  sbi_printf("\nKUBSan test: OOB shift\n");
  sbi_printf("Performing negative exponent right shift and left overflow shift in INT_MAX variable\n");

	val1 <<= neg;

	val2 <<= wrap;
}


void test_ubsan_out_of_bounds(void)
{
	int i = 4, j = 4, k = -1;
	volatile struct {
		char above[4]; /* Protect surrounding memory. */
		int arr[4];
		char below[4]; /* Protect surrounding memory. */
	} data;

  sbi_printf("\nKUBSan test: OOB write\n");
  sbi_printf("Attempting to write data in OOB space of a %d positions array\n", i);

	data.arr[j] = i;

	data.arr[k] = i;
}

void test_ubsan_load_invalid_value(void)
{
	volatile char *dst, *src;
	bool val, val2, *ptr;
	enum ubsan_test_enum eval, eval2, *eptr;
	unsigned char c = 0xff;

  sbi_printf("\nKUBSan test: Invalid load value\n");
  sbi_printf("Attempting to load a value with wrong type pointers\n");

	dst = (char *)&val;
	src = &c;
	*dst = *src;

	ptr = &val2;
	val2 = val;

	dst = (char *)&eval;
	src = &c;
	*dst = *src;

	eptr = &eval2;
	eval2 = eval;
}

#pragma GCC diagnostic pop
#endif
