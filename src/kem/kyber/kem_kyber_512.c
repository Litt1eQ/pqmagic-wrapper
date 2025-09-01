/**
 * \file kem_kyber_512.c
 * \brief Kyber512 algorithm implementation
 */

#include <stdlib.h>
#include "kem_kyber.h"

static PQMAGIC_STATUS kyber_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int result = pqmagic_kyber512_std_keypair(public_key, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS kyber_512_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    int result = pqmagic_kyber512_std_enc(ciphertext, shared_secret, public_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

static PQMAGIC_STATUS kyber_512_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    int result = pqmagic_kyber512_std_dec(shared_secret, ciphertext, secret_key);
    return (result == 0) ? PQMAGIC_SUCCESS : PQMAGIC_ERROR;
}

PQMAGIC_KEM *PQMAGIC_KEM_kyber_512_new(void) {
    PQMAGIC_KEM *kem = malloc(sizeof(PQMAGIC_KEM));
    if (kem == NULL) {
        return NULL;
    }
    
    kem->method_name = PQMAGIC_KEM_alg_kyber_512;
    kem->alg_version = "Round3";
    kem->claimed_nist_level = 1;
    kem->ind_cca = true;
    
    kem->length_public_key = PQMAGIC_KEM_kyber_512_length_public_key;
    kem->length_secret_key = PQMAGIC_KEM_kyber_512_length_secret_key;
    kem->length_ciphertext = PQMAGIC_KEM_kyber_512_length_ciphertext;
    kem->length_shared_secret = PQMAGIC_KEM_kyber_512_length_shared_secret;
    
    kem->keypair = kyber_512_keypair;
    kem->encaps = kyber_512_encaps;
    kem->decaps = kyber_512_decaps;
    
    return kem;
}
