/**
 * \file test_common.c
 * \brief Tests for common wrapper functionality
 */

#include "test_framework.h"
#include "pqmagic_wrapper.h"
#include <string.h>

/* Function prototype */
void test_common_functions(void);

void test_common_functions(void) {
    TEST_SUITE("Common Functions");
    
    TEST_CASE("PQMAGIC_version returns correct version");
    const char *version = PQMAGIC_version();
    ASSERT_NOT_NULL(version);
    ASSERT_STR_EQ(PQMAGIC_WRAPPER_VERSION, version);
    TEST_CASE_END();
    
    TEST_CASE("PQMAGIC_init and PQMAGIC_cleanup work");
    /* These functions should not crash */
    PQMAGIC_init();
    PQMAGIC_cleanup();
    PQMAGIC_init(); /* Should be safe to call multiple times */
    TEST_CASE_END();
}
