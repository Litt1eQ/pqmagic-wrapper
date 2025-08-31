/**
 * \file pqmagic_wrapper.h
 * \brief PQMagic wrapper library with liboqs-style API
 *
 * This wrapper provides a liboqs-style API for the PQMagic post-quantum
 * cryptographic library, supporting both KEM and signature algorithms.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PQMAGIC_WRAPPER_H
#define PQMAGIC_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Library version string
 */
#define PQMAGIC_WRAPPER_VERSION "1.0.0"

/**
 * API visibility macros
 */
#if defined(_WIN32)
#define PQMAGIC_API __declspec(dllexport)
#else
#define PQMAGIC_API __attribute__((visibility("default")))
#endif

/**
 * Status codes
 */
typedef enum {
    PQMAGIC_ERROR = -1,
    PQMAGIC_SUCCESS = 0,
    PQMAGIC_ERROR_INVALID_ALGORITHM = 1,
    PQMAGIC_ERROR_INVALID_PARAMETER = 2,
    PQMAGIC_ERROR_MEMORY_ALLOCATION = 3,
    PQMAGIC_ERROR_NOT_IMPLEMENTED = 4,
} PQMAGIC_STATUS;

/**
 * Get library version
 */
PQMAGIC_API const char *PQMAGIC_version(void);

/**
 * Initialize the library
 */
PQMAGIC_API void PQMAGIC_init(void);

/**
 * Cleanup library resources
 */
PQMAGIC_API void PQMAGIC_cleanup(void);

/*
 * ===============================
 *         KEM ALGORITHMS
 * ===============================
 */

/* Algorithm identifiers for KEM algorithms */
#define PQMAGIC_KEM_alg_ml_kem_512        "ML-KEM-512"
#define PQMAGIC_KEM_alg_ml_kem_768        "ML-KEM-768"
#define PQMAGIC_KEM_alg_ml_kem_1024       "ML-KEM-1024"
#define PQMAGIC_KEM_alg_kyber_512         "Kyber512"
#define PQMAGIC_KEM_alg_kyber_768         "Kyber768"
#define PQMAGIC_KEM_alg_kyber_1024        "Kyber1024"
#define PQMAGIC_KEM_alg_aigis_enc_1       "Aigis-Enc-1"
#define PQMAGIC_KEM_alg_aigis_enc_2       "Aigis-Enc-2"
#define PQMAGIC_KEM_alg_aigis_enc_3       "Aigis-Enc-3"
#define PQMAGIC_KEM_alg_aigis_enc_4       "Aigis-Enc-4"

/** Number of KEM algorithm identifiers */
#define PQMAGIC_KEM_algs_length 10

/**
 * KEM object structure
 */
typedef struct PQMAGIC_KEM {
    /** Algorithm name */
    const char *method_name;
    
    /** Algorithm version */
    const char *alg_version;
    
    /** NIST security level */
    uint8_t claimed_nist_level;
    
    /** Whether the KEM offers IND-CCA security */
    bool ind_cca;
    
    /** Key and ciphertext sizes */
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
    
    /** Function pointers */
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
    PQMAGIC_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
    
} PQMAGIC_KEM;

/**
 * Get KEM algorithm identifier by index
 */
PQMAGIC_API const char *PQMAGIC_KEM_alg_identifier(size_t i);

/**
 * Get number of available KEM algorithms
 */
PQMAGIC_API int PQMAGIC_KEM_alg_count(void);

/**
 * Check if KEM algorithm is enabled
 */
PQMAGIC_API int PQMAGIC_KEM_alg_is_enabled(const char *method_name);

/**
 * Create new KEM object
 */
PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_new(const char *method_name);

/**
 * Generate KEM keypair
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_KEM_keypair(const PQMAGIC_KEM *kem, uint8_t *public_key, uint8_t *secret_key);

/**
 * KEM encapsulation
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_KEM_encaps(const PQMAGIC_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);

/**
 * KEM decapsulation
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_KEM_decaps(const PQMAGIC_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

/**
 * Free KEM object
 */
PQMAGIC_API void PQMAGIC_KEM_free(PQMAGIC_KEM *kem);

/*
 * ===============================
 *      SIGNATURE ALGORITHMS
 * ===============================
 */

/* Algorithm identifiers for signature algorithms */
#define PQMAGIC_SIG_alg_ml_dsa_44         "ML-DSA-44"
#define PQMAGIC_SIG_alg_ml_dsa_65         "ML-DSA-65"
#define PQMAGIC_SIG_alg_ml_dsa_87         "ML-DSA-87"
#define PQMAGIC_SIG_alg_dilithium_2       "Dilithium2"
#define PQMAGIC_SIG_alg_dilithium_3       "Dilithium3"
#define PQMAGIC_SIG_alg_dilithium_5       "Dilithium5"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_128f "SLH-DSA-SHA2-128f"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_128s "SLH-DSA-SHA2-128s"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_192f "SLH-DSA-SHA2-192f"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_192s "SLH-DSA-SHA2-192s"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_256f "SLH-DSA-SHA2-256f"
#define PQMAGIC_SIG_alg_slh_dsa_sha2_256s "SLH-DSA-SHA2-256s"
#define PQMAGIC_SIG_alg_slh_dsa_shake_128f "SLH-DSA-SHAKE-128f"
#define PQMAGIC_SIG_alg_slh_dsa_shake_128s "SLH-DSA-SHAKE-128s"
#define PQMAGIC_SIG_alg_slh_dsa_shake_192f "SLH-DSA-SHAKE-192f"
#define PQMAGIC_SIG_alg_slh_dsa_shake_192s "SLH-DSA-SHAKE-192s"
#define PQMAGIC_SIG_alg_slh_dsa_shake_256f "SLH-DSA-SHAKE-256f"
#define PQMAGIC_SIG_alg_slh_dsa_shake_256s "SLH-DSA-SHAKE-256s"
#define PQMAGIC_SIG_alg_slh_dsa_sm3_128f   "SLH-DSA-SM3-128f"
#define PQMAGIC_SIG_alg_slh_dsa_sm3_128s   "SLH-DSA-SM3-128s"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_128f "SPHINCS-A-SHA2-128f"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_128s "SPHINCS-A-SHA2-128s"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_192f "SPHINCS-A-SHA2-192f"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_192s "SPHINCS-A-SHA2-192s"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_256f "SPHINCS-A-SHA2-256f"
#define PQMAGIC_SIG_alg_sphincs_a_sha2_256s "SPHINCS-A-SHA2-256s"
#define PQMAGIC_SIG_alg_sphincs_a_shake_128f "SPHINCS-A-SHAKE-128f"
#define PQMAGIC_SIG_alg_sphincs_a_shake_128s "SPHINCS-A-SHAKE-128s"
#define PQMAGIC_SIG_alg_sphincs_a_shake_192f "SPHINCS-A-SHAKE-192f"
#define PQMAGIC_SIG_alg_sphincs_a_shake_192s "SPHINCS-A-SHAKE-192s"
#define PQMAGIC_SIG_alg_sphincs_a_shake_256f "SPHINCS-A-SHAKE-256f"
#define PQMAGIC_SIG_alg_sphincs_a_shake_256s "SPHINCS-A-SHAKE-256s"
#define PQMAGIC_SIG_alg_sphincs_a_sm3_128f   "SPHINCS-A-SM3-128f"
#define PQMAGIC_SIG_alg_sphincs_a_sm3_128s   "SPHINCS-A-SM3-128s"
#define PQMAGIC_SIG_alg_aigis_sig_1       "Aigis-Sig-1"
#define PQMAGIC_SIG_alg_aigis_sig_2       "Aigis-Sig-2"
#define PQMAGIC_SIG_alg_aigis_sig_3       "Aigis-Sig-3"

/** Number of signature algorithm identifiers */
#define PQMAGIC_SIG_algs_length 37

/**
 * Signature object structure
 */
typedef struct PQMAGIC_SIG {
    /** Algorithm name */
    const char *method_name;
    
    /** Algorithm version */
    const char *alg_version;
    
    /** NIST security level */
    uint8_t claimed_nist_level;
    
    /** Security properties */
    bool euf_cma;
    bool suf_cma;
    bool sig_with_ctx_support;
    
    /** Key and signature sizes */
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
    
    /** Function pointers */
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*sign_with_ctx_str)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*verify)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
    PQMAGIC_STATUS (*verify_with_ctx_str)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
    
} PQMAGIC_SIG;

/**
 * Get signature algorithm identifier by index
 */
PQMAGIC_API const char *PQMAGIC_SIG_alg_identifier(size_t i);

/**
 * Get number of available signature algorithms
 */
PQMAGIC_API int PQMAGIC_SIG_alg_count(void);

/**
 * Check if signature algorithm is enabled
 */
PQMAGIC_API int PQMAGIC_SIG_alg_is_enabled(const char *method_name);

/**
 * Check if algorithm supports context string
 */
PQMAGIC_API bool PQMAGIC_SIG_supports_ctx_str(const char *alg_name);

/**
 * Create new signature object
 */
PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_new(const char *method_name);

/**
 * Generate signature keypair
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_SIG_keypair(const PQMAGIC_SIG *sig, uint8_t *public_key, uint8_t *secret_key);

/**
 * Sign message
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_SIG_sign(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * Sign message with context string
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_SIG_sign_with_ctx_str(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * Verify signature
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_SIG_verify(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * Verify signature with context string
 */
PQMAGIC_API PQMAGIC_STATUS PQMAGIC_SIG_verify_with_ctx_str(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

/**
 * Free signature object
 */
PQMAGIC_API void PQMAGIC_SIG_free(PQMAGIC_SIG *sig);

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // PQMAGIC_WRAPPER_H
