/**
 * \file example_sig.c
 * \brief Example program demonstrating signature usage
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

static int test_sig_algorithm(const char *alg_name) {
    printf("\n=== Testing Signature Algorithm: %s ===\n", alg_name);
    
    /* Check if algorithm is enabled */
    if (!PQMAGIC_SIG_alg_is_enabled(alg_name)) {
        printf("Algorithm %s is not enabled.\n", alg_name);
        return 0;
    }
    
    /* Create signature object */
    PQMAGIC_SIG *sig = PQMAGIC_SIG_new(alg_name);
    if (!sig) {
        printf("Failed to create signature object for %s\n", alg_name);
        return -1;
    }
    
    printf("Algorithm: %s\n", sig->method_name);
    printf("Version: %s\n", sig->alg_version);
    printf("NIST Level: %d\n", sig->claimed_nist_level);
    printf("EUF-CMA: %s\n", sig->euf_cma ? "Yes" : "No");
    printf("SUF-CMA: %s\n", sig->suf_cma ? "Yes" : "No");
    printf("Context string support: %s\n", sig->sig_with_ctx_support ? "Yes" : "No");
    printf("Public key size: %zu bytes\n", sig->length_public_key);
    printf("Secret key size: %zu bytes\n", sig->length_secret_key);
    printf("Signature size: %zu bytes\n", sig->length_signature);
    
    /* Allocate memory */
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    
    /* Test messages */
    const char *message = "Hello, PQMagic! This is a test message.";
    const char *wrong_message = "This is a different message.";
    size_t message_len = strlen(message);
    size_t wrong_message_len = strlen(wrong_message);
    size_t signature_len;
    PQMAGIC_STATUS status = PQMAGIC_SUCCESS;

    if (!public_key || !secret_key || !signature) {
        printf("Memory allocation failed\n");
        status = PQMAGIC_ERROR;
        goto cleanup;
    }
    
    /* Generate keypair */
    printf("\nGenerating keypair...\n");
    status = PQMAGIC_SIG_keypair(sig, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Keypair generation failed: %d\n", status);
        goto cleanup;
    }
    
    print_hex("Public key", public_key, sig->length_public_key);
    print_hex("Secret key", secret_key, sig->length_secret_key);
    
    /* Sign message */
    printf("\nSigning message: \"%s\"\n", message);
    status = PQMAGIC_SIG_sign(sig, signature, &signature_len, 
                             (const uint8_t*)message, message_len, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Signing failed: %d\n", status);
        goto cleanup;
    }
    
    printf("Signature length: %zu bytes\n", signature_len);
    print_hex("Signature", signature, signature_len);
    
    /* Verify correct message */
    printf("\nVerifying correct message...\n");
    status = PQMAGIC_SIG_verify(sig, (const uint8_t*)message, message_len, 
                               signature, signature_len, public_key);
    if (status == PQMAGIC_SUCCESS) {
        printf("✓ Verification successful!\n");
    } else {
        printf("✗ Verification failed: %d\n", status);
        goto cleanup;
    }
    
    /* Verify wrong message (should fail) */
    printf("\nVerifying wrong message (should fail)...\n");
    status = PQMAGIC_SIG_verify(sig, (const uint8_t*)wrong_message, wrong_message_len, 
                               signature, signature_len, public_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("✓ Verification correctly failed for wrong message!\n");
        status = PQMAGIC_SUCCESS;  /* Reset status after successful negative test */
    } else {
        printf("✗ Verification should have failed but didn't!\n");
        goto cleanup;
    }
    
    /* Test context string functionality if supported */
    if (sig->sig_with_ctx_support && sig->sign_with_ctx_str && sig->verify_with_ctx_str) {
        printf("\nTesting context string functionality...\n");
        
        const char *context = "test_context_2024";
        const char *wrong_context = "wrong_context";
        size_t context_len = strlen(context);
        size_t wrong_context_len = strlen(wrong_context);
        size_t ctx_signature_len;
        
        /* Sign with context */
        printf("Signing with context: \"%s\"\n", context);
        status = PQMAGIC_SIG_sign_with_ctx_str(sig, signature, &ctx_signature_len,
                                               (const uint8_t*)message, message_len,
                                               (const uint8_t*)context, context_len,
                                               secret_key);
        if (status != PQMAGIC_SUCCESS) {
            printf("Context signing failed: %d\n", status);
            goto cleanup;
        }
        
        printf("Context signature length: %zu bytes\n", ctx_signature_len);
        print_hex("Context signature", signature, ctx_signature_len);
        
        /* Verify with correct context */
        printf("Verifying with correct context...\n");
        status = PQMAGIC_SIG_verify_with_ctx_str(sig, (const uint8_t*)message, message_len,
                                                signature, ctx_signature_len,
                                                (const uint8_t*)context, context_len,
                                                public_key);
        if (status == PQMAGIC_SUCCESS) {
            printf("✓ Context verification successful!\n");
        } else {
            printf("✗ Context verification failed: %d\n", status);
            goto cleanup;
        }
        
        /* Verify with wrong context (should fail) */
        printf("Verifying with wrong context (should fail)...\n");
        status = PQMAGIC_SIG_verify_with_ctx_str(sig, (const uint8_t*)message, message_len,
                                                signature, ctx_signature_len,
                                                (const uint8_t*)wrong_context, wrong_context_len,
                                                public_key);
        if (status != PQMAGIC_SUCCESS) {
            printf("✓ Context verification correctly failed for wrong context!\n");
            status = PQMAGIC_SUCCESS;  /* Reset status after successful negative test */
        } else {
            printf("✗ Context verification should have failed but didn't!\n");
            goto cleanup;
        }
    } else {
        printf("\nContext strings not supported for this algorithm.\n");
    }
    
    printf("\n✓ SUCCESS: All tests passed for %s!\n", alg_name);
    
cleanup:
    free(public_key);
    free(secret_key);
    free(signature);
    PQMAGIC_SIG_free(sig);
    
    return (status == PQMAGIC_SUCCESS) ? 0 : -1;
}

int main(void) {
    printf("PQMagic Wrapper Signature Example\n");
    printf("Version: %s\n", PQMAGIC_version());
    
    /* Initialize the library */
    PQMAGIC_init();
    
    /* Test a few algorithms */
    const char *test_algorithms[] = {
        PQMAGIC_SIG_alg_ml_dsa_44,
        PQMAGIC_SIG_alg_ml_dsa_65,
        PQMAGIC_SIG_alg_ml_dsa_87,
        PQMAGIC_SIG_alg_dilithium_2,
        PQMAGIC_SIG_alg_dilithium_3,
        PQMAGIC_SIG_alg_dilithium_5,
        PQMAGIC_SIG_alg_slh_dsa_sha2_128f,
        PQMAGIC_SIG_alg_slh_dsa_sha2_128s,
        PQMAGIC_SIG_alg_slh_dsa_sha2_192f,
        PQMAGIC_SIG_alg_slh_dsa_sha2_192s,
        PQMAGIC_SIG_alg_slh_dsa_sha2_256f,
        PQMAGIC_SIG_alg_slh_dsa_sha2_256s,
        PQMAGIC_SIG_alg_slh_dsa_shake_128f,
        PQMAGIC_SIG_alg_slh_dsa_shake_128s,
        PQMAGIC_SIG_alg_slh_dsa_shake_192f,
        PQMAGIC_SIG_alg_slh_dsa_shake_192s,
        PQMAGIC_SIG_alg_slh_dsa_shake_256f,
        PQMAGIC_SIG_alg_slh_dsa_shake_256s,
        PQMAGIC_SIG_alg_slh_dsa_sm3_128f,
        PQMAGIC_SIG_alg_slh_dsa_sm3_128s,
        PQMAGIC_SIG_alg_sphincs_a_sha2_128f,
        PQMAGIC_SIG_alg_sphincs_a_sha2_128s,
        PQMAGIC_SIG_alg_sphincs_a_sha2_192f,
        PQMAGIC_SIG_alg_sphincs_a_sha2_192s,
        PQMAGIC_SIG_alg_sphincs_a_sha2_256f,
        PQMAGIC_SIG_alg_sphincs_a_sha2_256s,
        PQMAGIC_SIG_alg_sphincs_a_shake_128f,
        PQMAGIC_SIG_alg_sphincs_a_shake_128s,
        PQMAGIC_SIG_alg_sphincs_a_shake_192f,
        PQMAGIC_SIG_alg_sphincs_a_shake_192s,
        PQMAGIC_SIG_alg_sphincs_a_shake_256f,
        PQMAGIC_SIG_alg_sphincs_a_shake_256s,
        PQMAGIC_SIG_alg_sphincs_a_sm3_128f,
        PQMAGIC_SIG_alg_sphincs_a_sm3_128s,
        PQMAGIC_SIG_alg_aigis_sig_1,
        PQMAGIC_SIG_alg_aigis_sig_2,
        PQMAGIC_SIG_alg_aigis_sig_3,
    };
    
    int success_count = 0;
    int total_count = 0;
    
    for (size_t i = 0; i < sizeof(test_algorithms) / sizeof(test_algorithms[0]); i++) {
        total_count++;
        if (test_sig_algorithm(test_algorithms[i]) == 0) {
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
