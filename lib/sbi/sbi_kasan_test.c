
#ifdef KASAN_TESTS_ENABLED
#include <sbi/sbi_kasan_test.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"

void test_heap_overflow(void) {
  int oob_index = 18;
  int size = 17;
  unsigned char *ptr = sbi_malloc(size);//sbi_malloc(size);
  sbi_printf("\nKASan test: heap OOB write\n");
  sbi_printf("Writing 1 byte at offset %d in %d-byte heap buffer allocated at %p\n",
         oob_index, size, ptr);
  ptr[oob_index] = 0;
}

char oob_value;

void test_stack_overflow(void) {
  char buffer[17];
  int oob_index = 18;
  sbi_printf("\nKASan test: stack OOB read\n");
  sbi_printf("Reading 1 byte at offset %d in %ld-byte stack buffer at %p\n",
         oob_index, sizeof(buffer), (void*)&buffer);
  oob_value = buffer[oob_index];
}

int global_array[17];

void test_globals_overflow(void) {
  int oob_index = 18;
  sbi_printf("%p", &global_array);
  sbi_printf("\nKASan test: global OOB write\n");
  sbi_printf(
      "Writing an integer at index %d in %ld-element global integer array at "
      "%p\n",
      oob_index, sizeof(global_array) / sizeof(int), (void*)&global_array);
  global_array[oob_index] = 0;
}

char global_char_buffer[17];

void test_memset_overflow(void) {
  int oob_size = 18;
  sbi_printf("\nKASan test: memset OOB write in globals\n");
  sbi_printf("Memsetting global %ld-byte buffer at %p with %d values of 0xaa\n",
         sizeof(global_char_buffer), (void*)&global_char_buffer, oob_size);
  sbi_memset(global_char_buffer, 0xaa, oob_size);
}

void test_memcpy_overflow(void) {
  char buffer[18];
  int oob_size = sizeof(buffer);
  sbi_printf("\nKASan test: memcpy OOB read from globals\n");
  sbi_printf("Memcopying %d bytes from %ld-byte global buffer into local array\n",
         oob_size, sizeof(global_char_buffer));
  sbi_memcpy(buffer, global_char_buffer, oob_size);
}
#pragma GCC diagnostic pop
#endif