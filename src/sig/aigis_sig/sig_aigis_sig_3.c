/**
 * \file sig_aigis_sig_3.c
 * \brief Aigis-Sig-3 algorithm implementation
 */

#include <stdlib.h>
#include "sig_aigis_sig.h"

static PQMAGIC_STATUS aigis_sig_3_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_aigis_sig3_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_sig_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    int result = pqmagic_aigis_sig3_std_signature(signature, signature_len, message, message_len, NULL, 0, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_sig_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    int result = pqmagic_aigis_sig3_std_signature(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_sig_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    int result = pqmagic_aigis_sig3_std_verify(signature, signature_len, message, message_len, NULL, 0, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_sig_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    int result = pqmagic_aigis_sig3_std_verify(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_3_new(void) {
    PQMAGIC_SIG *sig = malloc(sizeof(PQMAGIC_SIG));
    if (sig == NULL) {
        return NULL;
    }
    
    sig->method_name = PQMAGIC_SIG_alg_aigis_sig_3;
    sig->alg_version = "Research";
    sig->claimed_nist_level = 5;
    sig->euf_cma = true;
    sig->suf_cma = false;
    sig->sig_with_ctx_support = true;  /* Aigis-Sig supports context strings */
    
    sig->length_public_key = PQMAGIC_SIG_aigis_sig_3_length_public_key;
    sig->length_secret_key = PQMAGIC_SIG_aigis_sig_3_length_secret_key;
    sig->length_signature = PQMAGIC_SIG_aigis_sig_3_length_signature;
    
    sig->keypair = aigis_sig_3_keypair;
    sig->sign = aigis_sig_3_sign;
    sig->sign_with_ctx_str = aigis_sig_3_sign_with_ctx_str;
    sig->verify = aigis_sig_3_verify;
    sig->verify_with_ctx_str = aigis_sig_3_verify_with_ctx_str;
    
    return sig;
}
