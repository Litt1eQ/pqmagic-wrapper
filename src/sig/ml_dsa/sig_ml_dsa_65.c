/**
 * \file sig_ml_dsa_65.c
 * \brief ML-DSA-65 algorithm implementation
 */

#include <stdlib.h>
#include "sig_ml_dsa.h"
#include "pqmagic_api.h"

static PQMAGIC_STATUS ml_dsa_65_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_ml_dsa_65_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_dsa_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    int result = pqmagic_ml_dsa_65_std_signature(signature, signature_len, message, message_len, NULL, 0, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_dsa_65_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    int result = pqmagic_ml_dsa_65_std_signature(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_dsa_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    int result = pqmagic_ml_dsa_65_std_verify(signature, signature_len, message, message_len, NULL, 0, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_dsa_65_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    int result = pqmagic_ml_dsa_65_std_verify(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_65_new(void) {
    PQMAGIC_SIG *sig = malloc(sizeof(PQMAGIC_SIG));
    if (sig == NULL) {
        return NULL;
    }
    
    sig->method_name = PQMAGIC_SIG_alg_ml_dsa_65;
    sig->alg_version = "FIPS204";
    sig->claimed_nist_level = 3;
    sig->euf_cma = true;
    sig->suf_cma = false;
    sig->sig_with_ctx_support = true;
    
    sig->length_public_key = PQMAGIC_SIG_ml_dsa_65_length_public_key;
    sig->length_secret_key = PQMAGIC_SIG_ml_dsa_65_length_secret_key;
    sig->length_signature = PQMAGIC_SIG_ml_dsa_65_length_signature;
    
    sig->keypair = ml_dsa_65_keypair;
    sig->sign = ml_dsa_65_sign;
    sig->sign_with_ctx_str = ml_dsa_65_sign_with_ctx_str;
    sig->verify = ml_dsa_65_verify;
    sig->verify_with_ctx_str = ml_dsa_65_verify_with_ctx_str;
    
    return sig;
}
