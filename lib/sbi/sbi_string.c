/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Atish Patra <atish.patra@wdc.com>
 */

/*
 * Simple libc functions. These are not optimized at all and might have some
 * bugs as well. Use any optimized routines from newlib or glibc if required.
 */

#include <sbi/sbi_string.h>
#include <sbi/sbi_kasan.h>

#define __RET_ADDR ((unsigned long) __builtin_return_address(0))
/*
  Provides sbi_strcmp for the completeness of supporting string functions.
  it is not recommended to use sbi_strcmp() but use sbi_strncmp instead.
*/
int sbi_strcmp(const char *a, const char *b)
{
    /* search first diff or end of string */
    for (; *a == *b && *a != '\0'; a++, b++)
        ;

    return *a - *b;
}

int sbi_strncmp(const char *a, const char *b, size_t count)
{
    /* search first diff or end of string */
    for (; count > 0 && *a == *b && *a != '\0'; a++, b++, count--)
        ;

    /* No difference till the end */
    if (!count)
        return 0;

    return *a - *b;
}

size_t sbi_strlen(const char *str)
{
    unsigned long ret = 0;

    while (*str != '\0') {
        ret++;
        str++;
    }

    return ret;
}

size_t sbi_strnlen(const char *str, size_t count)
{
    unsigned long ret = 0;

    while (*str != '\0' && ret < count) {
        ret++;
        str++;
    }

    return ret;
}

char *sbi_strcpy(char *dest, const char *src)
{
    char *ret = dest;

    while ((*dest++ = *src++) != '\0') {
    }
    return ret;
}

char *sbi_strncpy(char *dest, const char *src, size_t count)
{
    char *tmp = dest;

    while (count) {
        if ((*tmp = *src) != 0)
            src++;
        tmp++;
        count--;
    }
    return dest;
}

char *sbi_strchr(const char *s, int c)
{
    while (*s != '\0' && *s != (char)c)
        s++;

    if (*s == '\0')
        return NULL;
    else
        return (char *)s;
}

char *sbi_strrchr(const char *s, int c)
{
    const char *last = s + sbi_strlen(s);

    while (last > s && *last != (char)c)
        last--;

    if (*last != (char)c)
        return NULL;
    else
        return (char *)last;
}
#ifdef KASAN_ENABLED
__attribute__((no_sanitize("address")))
void *_real_sbi_memset(void *s, int c, size_t count){
        
    char *temp = s;

    while (count > 0) {
        count--;
        *temp++ = c;
    }

    return s;

}
__attribute__((no_sanitize("address")))
void *_real_sbi_memcpy(void *dest, const void *src, size_t count){
    
    char *temp1   = dest;
    const char *temp2 = src;

    while (count > 0) {
        *temp1++ = *temp2++;
        count--;
    }

    return dest;

}

__attribute__((no_sanitize("address")))
void *_real_sbi_memmove(void *dest, const void *src, size_t count)
{
    char *temp1   = (char *)dest;
    const char *temp2 = (char *)src;

    if (src == dest)
        return dest;

    if (dest < src) {
        while (count > 0) {
            *temp1++ = *temp2++;
            count--;
        }
    } else {
        temp1 = (char *)dest + count - 1;
        temp2 = (char *)src + count - 1;

        while (count > 0) {
            *temp1-- = *temp2--;
            count--;
        }
    }

    return dest;
}
#endif

__attribute__((no_sanitize("address")))
void *sbi_memset(void *s, int c, unsigned long count) {
    #ifdef KASAN_ENABLED
    kasan_shadow_check((unsigned long)s, count, true, __RET_ADDR);
    return _real_sbi_memset(s, c, count);
    #endif
    
    char *temp = s;

    while (count > 0) {
        count--;
        *temp++ = c;
    }

    return s;
}

__attribute__((no_sanitize("address")))
void *sbi_memcpy(void *dest, const void *src, unsigned long count) {
    #ifdef KASAN_ENABLED
    kasan_shadow_check((unsigned long)src, count, false, __RET_ADDR);
    kasan_shadow_check((unsigned long)dest, count, true, __RET_ADDR); 
    return _real_sbi_memcpy(dest, src, count);
   
    #endif
    
    char *temp1   = dest;
    const char *temp2 = src;

    while (count > 0) {
        *temp1++ = *temp2++;
        count--;
    }

    return dest;
}

__attribute__((no_sanitize("address")))
void *sbi_memmove(void *dest, const void *src, size_t count)
{
    #ifdef KASAN_ENABLED
    kasan_shadow_check((unsigned long)src, count, false, __RET_ADDR);
    kasan_shadow_check((unsigned long)dest, count, true, __RET_ADDR);
    return _real_sbi_memmove(dest, src, count);
    #endif
    
    char *temp1   = (char *)dest;
    const char *temp2 = (char *)src;

    if (src == dest)
        return dest;

    if (dest < src) {
        while (count > 0) {
            *temp1++ = *temp2++;
            count--;
        }
    } else {
        temp1 = (char *)dest + count - 1;
        temp2 = (char *)src + count - 1;

        while (count > 0) {
            *temp1-- = *temp2--;
            count--;
        }
    }

    return dest;
}

int sbi_memcmp(const void *s1, const void *s2, size_t count)
{
    const char *temp1 = s1;
    const char *temp2 = s2;

    for (; count > 0 && (*temp1 == *temp2); count--) {
        temp1++;
        temp2++;
    }

    if (count > 0)
        return *(unsigned char *)temp1 - *(unsigned char *)temp2;
    else
        return 0;
}

void *sbi_memchr(const void *s, int c, size_t count)
{
    const unsigned char *temp = s;

    while (count > 0) {
        if ((unsigned char)c == *temp++) {
            return (void *)(temp - 1);
        }
        count--;
    }

    return NULL;
}

__attribute__((no_sanitize("address")))
void *memset(void *s, int c, size_t count)
{
    #ifdef KASAN_ENABLED
    kasan_shadow_check((unsigned long)s, count, true, __RET_ADDR);
    #endif
    char *temp = s;

    while (count > 0) {
        count--;
        *temp++ = c;
    }

    return s;
}

__attribute__((no_sanitize("address")))
void *memcpy(void *dest, const void *src, size_t count)
{
    #ifdef KASAN_ENABLED
    kasan_shadow_check((unsigned long)src, count, false, __RET_ADDR);
    kasan_shadow_check((unsigned long)dest, count, true, __RET_ADDR); 
    #endif
    char *temp1   = dest;
    const char *temp2 = src;

    while (count > 0) {
        *temp1++ = *temp2++;
        count--;
    }

    return dest;
}
