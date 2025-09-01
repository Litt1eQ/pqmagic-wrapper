/**
 * \file sig_dilithium_5.c
 * \brief Dilithium5 algorithm implementation
 */

#include <stdlib.h>
#include "sig_dilithium.h"

static PQMAGIC_STATUS dilithium_5_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_dilithium5_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS dilithium_5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    int result = pqmagic_dilithium5_std_signature(signature, signature_len, message, message_len, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS dilithium_5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    /* Dilithium doesn't support context strings - use standard sign */
    (void)ctx_str;  /* Suppress unused parameter warning */
    (void)ctx_str_len;
    return dilithium_5_sign(signature, signature_len, message, message_len, secret_key);
}

static PQMAGIC_STATUS dilithium_5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    int result = pqmagic_dilithium5_std_verify(signature, signature_len, message, message_len, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS dilithium_5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    /* Dilithium doesn't support context strings - use standard verify */
    (void)ctx_str;  /* Suppress unused parameter warning */
    (void)ctx_str_len;
    return dilithium_5_verify(message, message_len, signature, signature_len, public_key);
}

PQMAGIC_SIG *PQMAGIC_SIG_dilithium_5_new(void) {
    PQMAGIC_SIG *sig = malloc(sizeof(PQMAGIC_SIG));
    if (sig == NULL) {
        return NULL;
    }
    
    sig->method_name = PQMAGIC_SIG_alg_dilithium_5;
    sig->alg_version = "Round3";
    sig->claimed_nist_level = 5;
    sig->euf_cma = true;
    sig->suf_cma = false;
    sig->sig_with_ctx_support = false;  /* Dilithium doesn't support context strings */
    
    sig->length_public_key = PQMAGIC_SIG_dilithium_5_length_public_key;
    sig->length_secret_key = PQMAGIC_SIG_dilithium_5_length_secret_key;
    sig->length_signature = PQMAGIC_SIG_dilithium_5_length_signature;
    
    sig->keypair = dilithium_5_keypair;
    sig->sign = dilithium_5_sign;
    sig->sign_with_ctx_str = dilithium_5_sign_with_ctx_str;  /* Fallback to standard sign */
    sig->verify = dilithium_5_verify;
    sig->verify_with_ctx_str = dilithium_5_verify_with_ctx_str;  /* Fallback to standard verify */
    
    return sig;
}
