#ifdef KASAN_TESTS_ENABLED
#include <sbi/sbi_kasan_test.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"

int global_int_arr[17];

void globals_kasan_test(void) {
    int overflow_idx = 18;
    sbi_printf("\n*** KASAn global overflow test ***\n");
    sbi_printf("Global array: %lu elements (int), base address: %p\n",
               sizeof(global_int_arr) / sizeof(int), (void*)&global_int_arr);
    sbi_printf("Writing integer to index %d (overflow)\n", overflow_idx);
    global_int_arr[overflow_idx] = 0;
}

void heap_kasan_test(void) {
    int bad_idx = 18;
    int alloc_sz = 17;
    unsigned char *mem_ptr = sbi_malloc(alloc_sz);
    sbi_printf("\n*** KASAn heap overflow test ***\n");
    sbi_printf("Allocated buffer: %d bytes at address %p\n", alloc_sz, mem_ptr);
    sbi_printf("Writing to index %d (overflow by %d bytes)\n", bad_idx, bad_idx - alloc_sz + 1);
    mem_ptr[bad_idx] = 0;
}

char stack_read_result;

void stack_kasan_test(void) {
    char local_buf[17];
    int invalid_idx = 17;
    sbi_printf("\n*** KASAn stack overflow test ***\n");
    sbi_printf("Stack buffer size: %lu bytes, location: %p\n",
               sizeof(local_buf), (void*)&local_buf);
    sbi_printf("Reading from index %d (overflow by %d bytes)\n",
               invalid_idx, invalid_idx - (int)sizeof(local_buf) + 1);
    stack_read_result = local_buf[invalid_idx];
}

char global_byte_buf[17];

void memset_kasan_test(void) {
    int write_sz = 18;
    sbi_printf("\n*** KASAn memset overflow test ***\n");
    sbi_printf("Target buffer: %lu bytes at %p\n",
               sizeof(global_byte_buf), (void*)&global_byte_buf);
    sbi_printf("Memset size: %d bytes with pattern 0xaa (overflow by 1)\n", write_sz);
    sbi_memset(global_byte_buf, 0xaa, write_sz);
}

void memcpy_kasan_test(void) {
    char dest_buf[18];
    int copy_sz = sizeof(dest_buf);
    sbi_printf("\n*** KASAN memcpy overflow test ***\n");
    sbi_printf("Source: %lu bytes (global_byte_buf)\n", sizeof(global_byte_buf));
    sbi_printf("Copying %d bytes to local buffer (read overflow by 1)\n", copy_sz);
    sbi_memcpy(dest_buf, global_byte_buf, copy_sz);
}

#pragma GCC diagnostic pop
#endif