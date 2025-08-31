/**
 * \file test_main.c
 * \brief Main test runner for PQMagic wrapper
 */

#include <stdio.h>
#include <stdlib.h>
#include "test_framework.h"
#include "pqmagic_wrapper.h"

/* Global test results */
test_results_t g_test_results = {0};

/* Test function declarations */
void test_common_functions(void);
void test_kem_functions(void);
void test_sig_functions(void);

int main(void) {
    TEST_START();
    
    /* Initialize the library */
    PQMAGIC_init();
    
    /* Run test suites */
    test_common_functions();
    test_kem_functions();
    test_sig_functions();
    
    /* Cleanup */
    PQMAGIC_cleanup();
    
    TEST_END();
}
