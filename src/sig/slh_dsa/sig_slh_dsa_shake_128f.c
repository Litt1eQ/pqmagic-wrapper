/**
 * \file sig_slh_dsa_shake_128f.c
 * \brief SLH-DSA-SHAKE-128f algorithm implementation
 */

#include <stdlib.h>
#include "sig_slh_dsa.h"
#include "pqmagic_api.h"

static PQMAGIC_STATUS slh_dsa_shake_128f_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS slh_dsa_shake_128f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    int result = pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(signature, signature_len, message, message_len, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS slh_dsa_shake_128f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    (void)ctx_str; (void)ctx_str_len;
    return slh_dsa_shake_128f_sign(signature, signature_len, message, message_len, secret_key);
}

static PQMAGIC_STATUS slh_dsa_shake_128f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    int result = pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(signature, signature_len, message, message_len, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS slh_dsa_shake_128f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    (void)ctx_str; (void)ctx_str_len;
    return slh_dsa_shake_128f_verify(message, message_len, signature, signature_len, public_key);
}

PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_128f_new(void) {
    PQMAGIC_SIG *sig = malloc(sizeof(PQMAGIC_SIG));
    if (sig == NULL) return NULL;
    
    sig->method_name = PQMAGIC_SIG_alg_slh_dsa_shake_128f;
    sig->alg_version = "FIPS205";
    sig->claimed_nist_level = 1;
    sig->euf_cma = true; sig->suf_cma = false; sig->sig_with_ctx_support = false;
    
    sig->length_public_key = PQMAGIC_SIG_slh_dsa_shake_128f_length_public_key;
    sig->length_secret_key = PQMAGIC_SIG_slh_dsa_shake_128f_length_secret_key;
    sig->length_signature = PQMAGIC_SIG_slh_dsa_shake_128f_length_signature;
    
    sig->keypair = slh_dsa_shake_128f_keypair;
    sig->sign = slh_dsa_shake_128f_sign;
    sig->sign_with_ctx_str = slh_dsa_shake_128f_sign_with_ctx_str;
    sig->verify = slh_dsa_shake_128f_verify;
    sig->verify_with_ctx_str = slh_dsa_shake_128f_verify_with_ctx_str;
    
    return sig;
}
