/**
 * \file kem.c
 * \brief KEM algorithm registry and factory methods
 */

#include "pqmagic_wrapper.h"
#include "ml_kem/kem_ml_kem.h"
#include "kyber/kem_kyber.h"
#include "aigis_enc/kem_aigis_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Algorithm registry */
static const char *kem_alg_names[PQMAGIC_KEM_algs_length] = {
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

const char *PQMAGIC_KEM_alg_identifier(size_t i) {
    if (i >= PQMAGIC_KEM_algs_length) {
        return NULL;
    }
    return kem_alg_names[i];
}

int PQMAGIC_KEM_alg_count(void) {
    return PQMAGIC_KEM_algs_length;
}

int PQMAGIC_KEM_alg_is_enabled(const char *method_name) {
    if (method_name == NULL) {
        return 0;
    }
    
    for (size_t i = 0; i < PQMAGIC_KEM_algs_length; i++) {
        if (strcmp(method_name, kem_alg_names[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

PQMAGIC_KEM *PQMAGIC_KEM_new(const char *method_name) {
    if (method_name == NULL) {
        return NULL;
    }
    
    /* ML-KEM family */
    if (strcmp(method_name, PQMAGIC_KEM_alg_ml_kem_512) == 0) {
        return PQMAGIC_KEM_ml_kem_512_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_ml_kem_768) == 0) {
        return PQMAGIC_KEM_ml_kem_768_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_ml_kem_1024) == 0) {
        return PQMAGIC_KEM_ml_kem_1024_new();
    }
    
    /* Kyber family */
    else if (strcmp(method_name, PQMAGIC_KEM_alg_kyber_512) == 0) {
        return PQMAGIC_KEM_kyber_512_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_kyber_768) == 0) {
        return PQMAGIC_KEM_kyber_768_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_kyber_1024) == 0) {
        return PQMAGIC_KEM_kyber_1024_new();
    }
    
    /* Aigis-Enc family */
    else if (strcmp(method_name, PQMAGIC_KEM_alg_aigis_enc_1) == 0) {
        return PQMAGIC_KEM_aigis_enc_1_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_aigis_enc_2) == 0) {
        return PQMAGIC_KEM_aigis_enc_2_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_aigis_enc_3) == 0) {
        return PQMAGIC_KEM_aigis_enc_3_new();
    } else if (strcmp(method_name, PQMAGIC_KEM_alg_aigis_enc_4) == 0) {
        return PQMAGIC_KEM_aigis_enc_4_new();
    }
    
    return NULL;
}

PQMAGIC_STATUS PQMAGIC_KEM_keypair(const PQMAGIC_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
    if (kem == NULL || kem->keypair == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return kem->keypair(public_key, secret_key);
}

PQMAGIC_STATUS PQMAGIC_KEM_encaps(const PQMAGIC_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    if (kem == NULL || kem->encaps == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return kem->encaps(ciphertext, shared_secret, public_key);
}

PQMAGIC_STATUS PQMAGIC_KEM_decaps(const PQMAGIC_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    if (kem == NULL || kem->decaps == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return kem->decaps(shared_secret, ciphertext, secret_key);
}

void PQMAGIC_KEM_free(PQMAGIC_KEM *kem) {
    if (kem != NULL) {
        free(kem);
    }
}
