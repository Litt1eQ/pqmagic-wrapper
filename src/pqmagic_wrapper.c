/**
 * \file pqmagic_wrapper.c
 * \brief Main implementation file for PQMagic wrapper
 * 
 * This file contains the main library entry points and initialization code.
 */

#include "pqmagic_wrapper.h"
#include <stdio.h>
#include <stdlib.h>

/* Library initialization flag */
static int g_library_initialized = 0;

const char *PQMAGIC_version(void) {
    return PQMAGIC_WRAPPER_VERSION;
}

void PQMAGIC_init(void) {
    if (g_library_initialized) {
        return;
    }
    
    /* Initialize any global state if needed */
    /* For now, PQMagic doesn't require special initialization */
    
    g_library_initialized = 1;
}

void PQMAGIC_cleanup(void) {
    if (!g_library_initialized) {
        return;
    }
    
    /* Cleanup any global state if needed */
    /* For now, no special cleanup is required */
    
    g_library_initialized = 0;
}
