/**
 * \file example_kem.c
 * \brief Example program demonstrating KEM usage
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqmagic_wrapper.h"

static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf(" (%zu bytes)\n", len);
}

static int test_kem_algorithm(const char *alg_name) {
    printf("\n=== Testing KEM Algorithm: %s ===\n", alg_name);
    
    /* Check if algorithm is enabled */
    if (!PQMAGIC_KEM_alg_is_enabled(alg_name)) {
        printf("Algorithm %s is not enabled.\n", alg_name);
        return 0;
    }
    
    /* Create KEM object */
    PQMAGIC_KEM *kem = PQMAGIC_KEM_new(alg_name);
    if (!kem) {
        printf("Failed to create KEM object for %s\n", alg_name);
        return -1;
    }
    
    printf("Algorithm: %s\n", kem->method_name);
    printf("Version: %s\n", kem->alg_version);
    printf("NIST Level: %d\n", kem->claimed_nist_level);
    printf("IND-CCA: %s\n", kem->ind_cca ? "Yes" : "No");
    printf("Public key size: %zu bytes\n", kem->length_public_key);
    printf("Secret key size: %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext size: %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret size: %zu bytes\n", kem->length_shared_secret);
    
    /* Allocate memory */
    PQMAGIC_STATUS status = PQMAGIC_ERROR;
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret1 = malloc(kem->length_shared_secret);
    uint8_t *shared_secret2 = malloc(kem->length_shared_secret);
    
    if (!public_key || !secret_key || !ciphertext || !shared_secret1 || !shared_secret2) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Generate keypair */
    printf("\nGenerating keypair...\n");
    status = PQMAGIC_KEM_keypair(kem, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Keypair generation failed: %d\n", status);
        goto cleanup;
    }
    
    print_hex("Public key", public_key, kem->length_public_key);
    print_hex("Secret key", secret_key, kem->length_secret_key);
    
    /* Encapsulate */
    printf("\nPerforming encapsulation...\n");
    status = PQMAGIC_KEM_encaps(kem, ciphertext, shared_secret1, public_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Encapsulation failed: %d\n", status);
        goto cleanup;
    }
    
    print_hex("Ciphertext", ciphertext, kem->length_ciphertext);
    print_hex("Shared secret (encaps)", shared_secret1, kem->length_shared_secret);
    
    /* Decapsulate */
    printf("\nPerforming decapsulation...\n");
    status = PQMAGIC_KEM_decaps(kem, shared_secret2, ciphertext, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Decapsulation failed: %d\n", status);
        goto cleanup;
    }
    
    print_hex("Shared secret (decaps)", shared_secret2, kem->length_shared_secret);
    
    /* Verify shared secrets match */
    if (memcmp(shared_secret1, shared_secret2, kem->length_shared_secret) == 0) {
        printf("\n✓ SUCCESS: Shared secrets match!\n");
    } else {
        printf("\n✗ FAIL: Shared secrets do not match!\n");
        goto cleanup;
    }
    
cleanup:
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret1);
    free(shared_secret2);
    PQMAGIC_KEM_free(kem);
    
    return (status == PQMAGIC_SUCCESS) ? 0 : -1;
}

int main(void) {
    printf("PQMagic Wrapper KEM Example\n");
    printf("Version: %s\n", PQMAGIC_version());
    
    /* Initialize the library */
    PQMAGIC_init();
    
    /* Test a few algorithms */
    const char *test_algorithms[] = {
        PQMAGIC_KEM_alg_ml_kem_512,
        PQMAGIC_KEM_alg_ml_kem_768,
        PQMAGIC_KEM_alg_ml_kem_1024,
        PQMAGIC_KEM_alg_kyber_512,
        PQMAGIC_KEM_alg_kyber_768,
        PQMAGIC_KEM_alg_kyber_1024,
        PQMAGIC_KEM_alg_aigis_enc_1,
        PQMAGIC_KEM_alg_aigis_enc_2,
        PQMAGIC_KEM_alg_aigis_enc_3,
        PQMAGIC_KEM_alg_aigis_enc_4,
    };
    
    int success_count = 0;
    int total_count = 0;
    
    for (size_t i = 0; i < sizeof(test_algorithms) / sizeof(test_algorithms[0]); i++) {
        total_count++;
        if (test_kem_algorithm(test_algorithms[i]) == 0) {
            success_count++;
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Tested %d algorithms\n", total_count);
    printf("Successful: %d\n", success_count);
    printf("Failed: %d\n", total_count - success_count);
    
    /* Cleanup */
    PQMAGIC_cleanup();
    
    return (success_count == total_count) ? 0 : 1;
}
