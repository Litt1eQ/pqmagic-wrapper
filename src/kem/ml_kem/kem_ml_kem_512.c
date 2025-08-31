/**
 * \file kem_ml_kem_512.c
 * \brief ML-KEM-512 algorithm implementation
 */

#include <stdlib.h>
#include "kem_ml_kem.h"
#include "pqmagic_api.h"

static PQMAGIC_STATUS ml_kem_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_ml_kem_512_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_kem_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    int result = pqmagic_ml_kem_512_std_enc(ciphertext, shared_secret, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS ml_kem_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    int result = pqmagic_ml_kem_512_std_dec(shared_secret, ciphertext, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_512_new(void) {
    PQMAGIC_KEM *kem = malloc(sizeof(PQMAGIC_KEM));
    if (kem == NULL) {
        return NULL;
    }
    
    kem->method_name = PQMAGIC_KEM_alg_ml_kem_512;
    kem->alg_version = "FIPS203";
    kem->claimed_nist_level = 1;
    kem->ind_cca = true;
    
    kem->length_public_key = PQMAGIC_KEM_ml_kem_512_length_public_key;
    kem->length_secret_key = PQMAGIC_KEM_ml_kem_512_length_secret_key;
    kem->length_ciphertext = PQMAGIC_KEM_ml_kem_512_length_ciphertext;
    kem->length_shared_secret = PQMAGIC_KEM_ml_kem_512_length_shared_secret;
    
    kem->keypair = ml_kem_512_keypair;
    kem->encaps = ml_kem_512_encaps;
    kem->decaps = ml_kem_512_decaps;
    
    return kem;
}
