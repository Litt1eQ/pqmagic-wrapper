/**
 * \file sig.c
 * \brief Signature algorithm registry and factory methods
 */

#include "pqmagic_wrapper.h"
#include "ml_dsa/sig_ml_dsa.h"
#include "dilithium/sig_dilithium.h"
#include "slh_dsa/sig_slh_dsa.h"
#include "sphincs_alpha/sig_sphincs_alpha.h"
#include "aigis_sig/sig_aigis_sig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Algorithm registry */
static const char *sig_alg_names[PQMAGIC_SIG_algs_length] = {
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

const char *PQMAGIC_SIG_alg_identifier(size_t i) {
    if (i >= PQMAGIC_SIG_algs_length) {
        return NULL;
    }
    return sig_alg_names[i];
}

int PQMAGIC_SIG_alg_count(void) {
    return PQMAGIC_SIG_algs_length;
}

int PQMAGIC_SIG_alg_is_enabled(const char *method_name) {
    if (method_name == NULL) {
        return 0;
    }
    
    for (size_t i = 0; i < PQMAGIC_SIG_algs_length; i++) {
        if (strcmp(method_name, sig_alg_names[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

bool PQMAGIC_SIG_supports_ctx_str(const char *alg_name) {
    if (alg_name == NULL) {
        return false;
    }
    
    /* ML-DSA and Aigis-Sig support context strings */
    if (strncmp(alg_name, "ML-DSA", 6) == 0 || 
        strncmp(alg_name, "Aigis-Sig", 9) == 0) {
        return true;
    }
    
    return false;
}

PQMAGIC_SIG *PQMAGIC_SIG_new(const char *method_name) {
    if (method_name == NULL) {
        return NULL;
    }
    
    /* ML-DSA family */
    if (strcmp(method_name, PQMAGIC_SIG_alg_ml_dsa_44) == 0) {
        return PQMAGIC_SIG_ml_dsa_44_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_ml_dsa_65) == 0) {
        return PQMAGIC_SIG_ml_dsa_65_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_ml_dsa_87) == 0) {
        return PQMAGIC_SIG_ml_dsa_87_new();
    }
    
    /* Dilithium family */
    else if (strcmp(method_name, PQMAGIC_SIG_alg_dilithium_2) == 0) {
        return PQMAGIC_SIG_dilithium_2_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_dilithium_3) == 0) {
        return PQMAGIC_SIG_dilithium_3_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_dilithium_5) == 0) {
        return PQMAGIC_SIG_dilithium_5_new();
    }
    
    /* SLH-DSA family */
    else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_128f) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_128s) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_128s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_192f) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_192f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_192s) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_192s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_256f) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_256f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sha2_256s) == 0) {
        return PQMAGIC_SIG_slh_dsa_sha2_256s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_128f) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_128s) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_128s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_192f) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_192f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_192s) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_192s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_256f) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_256f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_shake_256s) == 0) {
        return PQMAGIC_SIG_slh_dsa_shake_256s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sm3_128f) == 0) {
        return PQMAGIC_SIG_slh_dsa_sm3_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_slh_dsa_sm3_128s) == 0) {
        return PQMAGIC_SIG_slh_dsa_sm3_128s_new();
    }
    
    /* SPHINCS-Alpha family */
    else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_128f) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_128s) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_128s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_128f) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_128s) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_128s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sm3_128f) == 0) {
        return PQMAGIC_SIG_sphincs_a_sm3_128f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sm3_128s) == 0) {
        return PQMAGIC_SIG_sphincs_a_sm3_128s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_192f) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_192f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_192s) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_192s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_256f) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_256f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_sha2_256s) == 0) {
        return PQMAGIC_SIG_sphincs_a_sha2_256s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_192f) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_192f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_192s) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_192s_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_256f) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_256f_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_sphincs_a_shake_256s) == 0) {
        return PQMAGIC_SIG_sphincs_a_shake_256s_new();
    }
    
    /* Aigis-Sig family */
    else if (strcmp(method_name, PQMAGIC_SIG_alg_aigis_sig_1) == 0) {
        return PQMAGIC_SIG_aigis_sig_1_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_aigis_sig_2) == 0) {
        return PQMAGIC_SIG_aigis_sig_2_new();
    } else if (strcmp(method_name, PQMAGIC_SIG_alg_aigis_sig_3) == 0) {
        return PQMAGIC_SIG_aigis_sig_3_new();
    }
    
    return NULL;
}

PQMAGIC_STATUS PQMAGIC_SIG_keypair(const PQMAGIC_SIG *sig, uint8_t *public_key, uint8_t *secret_key) {
    if (sig == NULL || sig->keypair == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return sig->keypair(public_key, secret_key);
}

PQMAGIC_STATUS PQMAGIC_SIG_sign(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    if (sig == NULL || sig->sign == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return sig->sign(signature, signature_len, message, message_len, secret_key);
}

PQMAGIC_STATUS PQMAGIC_SIG_sign_with_ctx_str(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    if (sig == NULL || sig->sign_with_ctx_str == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return sig->sign_with_ctx_str(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
}

PQMAGIC_STATUS PQMAGIC_SIG_verify(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    if (sig == NULL || sig->verify == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return sig->verify(message, message_len, signature, signature_len, public_key);
}

PQMAGIC_STATUS PQMAGIC_SIG_verify_with_ctx_str(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    if (sig == NULL || sig->verify_with_ctx_str == NULL) {
        return PQMAGIC_ERROR_INVALID_PARAMETER;
    }
    return sig->verify_with_ctx_str(message, message_len, signature, signature_len, ctx_str, ctx_str_len, public_key);
}

void PQMAGIC_SIG_free(PQMAGIC_SIG *sig) {
    if (sig != NULL) {
        free(sig);
    }
}
