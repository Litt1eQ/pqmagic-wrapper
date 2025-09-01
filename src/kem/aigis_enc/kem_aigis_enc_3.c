/**
 * \file kem_aigis_enc_3.c
 * \brief Aigis-Enc-3 algorithm implementation
 */

#include <stdlib.h>
#include "kem_aigis_enc.h"

static PQMAGIC_STATUS aigis_enc_3_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_aigis_enc_3_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_enc_3_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    int result = pqmagic_aigis_enc_3_std_enc(ciphertext, shared_secret, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS aigis_enc_3_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    int result = pqmagic_aigis_enc_3_std_dec(shared_secret, ciphertext, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_3_new(void) {
    PQMAGIC_KEM *kem = malloc(sizeof(PQMAGIC_KEM));
    if (kem == NULL) {
        return NULL;
    }
    
    kem->method_name = PQMAGIC_KEM_alg_aigis_enc_3;
    kem->alg_version = "Research";
    kem->claimed_nist_level = 3;
    kem->ind_cca = true;
    
    kem->length_public_key = PQMAGIC_KEM_aigis_enc_3_length_public_key;
    kem->length_secret_key = PQMAGIC_KEM_aigis_enc_3_length_secret_key;
    kem->length_ciphertext = PQMAGIC_KEM_aigis_enc_3_length_ciphertext;
    kem->length_shared_secret = PQMAGIC_KEM_aigis_enc_3_length_shared_secret;
    
    kem->keypair = aigis_enc_3_keypair;
    kem->encaps = aigis_enc_3_encaps;
    kem->decaps = aigis_enc_3_decaps;
    
    return kem;
}
