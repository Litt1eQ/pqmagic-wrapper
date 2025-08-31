/**
 * \file test_framework.h
 * \brief Minimal unit testing framework
 * 
 * A lightweight testing framework inspired by popular C testing libraries.
 * Can be used standalone or with libcheck if available.
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Test result tracking */
typedef struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
    int current_test_passed;
    const char *current_test_name;
} test_results_t;

extern test_results_t g_test_results;

/* Color output (if supported) */
#ifndef NO_COLOR
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET  "\033[0m"
#else
#define COLOR_GREEN  ""
#define COLOR_RED    ""
#define COLOR_YELLOW ""
#define COLOR_RESET  ""
#endif

/* Test macros */
#define TEST_START() \
    do { \
        g_test_results.total_tests = 0; \
        g_test_results.passed_tests = 0; \
        g_test_results.failed_tests = 0; \
        printf("Starting test suite...\n\n"); \
    } while(0)

#define TEST_END() \
    do { \
        printf("\n" COLOR_YELLOW "Test Results:" COLOR_RESET "\n"); \
        printf("  Total:  %d\n", g_test_results.total_tests); \
        printf("  " COLOR_GREEN "Passed: %d" COLOR_RESET "\n", g_test_results.passed_tests); \
        printf("  " COLOR_RED "Failed: %d" COLOR_RESET "\n", g_test_results.failed_tests); \
        if (g_test_results.failed_tests > 0) { \
            printf("\n" COLOR_RED "SOME TESTS FAILED" COLOR_RESET "\n"); \
            return EXIT_FAILURE; \
        } else { \
            printf("\n" COLOR_GREEN "ALL TESTS PASSED" COLOR_RESET "\n"); \
            return EXIT_SUCCESS; \
        } \
    } while(0)

#define TEST_SUITE(name) \
    printf(COLOR_YELLOW "=== %s ===" COLOR_RESET "\n", name)

#define TEST_CASE(name) \
    do { \
        g_test_results.current_test_name = name; \
        g_test_results.current_test_passed = 1; \
        g_test_results.total_tests++; \
        printf("  %-50s ... ", name); \
        fflush(stdout); \
    } while(0)

#define TEST_CASE_END() \
    do { \
        if (g_test_results.current_test_passed) { \
            g_test_results.passed_tests++; \
            printf(COLOR_GREEN "PASS" COLOR_RESET "\n"); \
        } else { \
            g_test_results.failed_tests++; \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
        } \
    } while(0)

/* Assertion macros */
#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Assertion failed: %s\n", #condition); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_FALSE(condition) \
    ASSERT_TRUE(!(condition))

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected: %ld, Actual: %ld\n", (long)(expected), (long)(actual)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_NE(expected, actual) \
    do { \
        if ((expected) == (actual)) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected not equal to: %ld, Actual: %ld\n", (long)(expected), (long)(actual)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected NULL, got: %p\n", (void*)(ptr)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected non-NULL pointer\n"); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected: \"%s\", Actual: \"%s\"\n", (expected), (actual)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_MEM_EQ(expected, actual, len) \
    do { \
        if (memcmp((expected), (actual), (len)) != 0) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Memory comparison failed (%zu bytes)\n", (size_t)(len)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

/* Additional assertion macros */
#define ASSERT_SUCCESS(status) \
    do { \
        if ((status) != PQMAGIC_SUCCESS) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected: PQMAGIC_SUCCESS, Actual: %d\n", (status)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_ERROR(status) \
    do { \
        if ((status) == PQMAGIC_SUCCESS) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected error status, got PQMAGIC_SUCCESS\n"); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_GT(val1, val2) \
    do { \
        if ((val1) <= (val2)) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected %ld > %ld\n", (long)(val1), (long)(val2)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

#define ASSERT_GE(val1, val2) \
    do { \
        if ((val1) < (val2)) { \
            printf(COLOR_RED "FAIL" COLOR_RESET "\n"); \
            printf("    Expected %ld >= %ld\n", (long)(val1), (long)(val2)); \
            printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
            g_test_results.current_test_passed = 0; \
        } \
    } while(0)

/* Test skip macro */
#define SKIP_TEST(reason) \
    do { \
        printf(COLOR_YELLOW "SKIP" COLOR_RESET " - %s\n", reason); \
        g_test_results.total_tests--; \
        return; \
    } while(0)

/* Utility functions */
static inline void test_print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("    %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1 && (i + 1) % 16 == 0) printf("\n         ");
    }
    printf("\n");
}

/* Test buffer corruption detection */
typedef struct {
    uint8_t magic[16];
} test_magic_t;

static inline void test_set_magic(uint8_t *buffer, size_t offset) {
    test_magic_t *magic = (test_magic_t*)(buffer + offset);
    memcpy(magic->magic, "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0", 16);
}

static inline bool test_check_magic(const uint8_t *buffer, size_t offset) {
    const test_magic_t *magic = (const test_magic_t*)(buffer + offset);
    return memcmp(magic->magic, "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0", 16) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* TEST_FRAMEWORK_H */
