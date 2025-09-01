/**
 * \file kem_ml_kem.h
 * \brief ML-KEM family algorithm declarations
 */

#ifndef KEM_ML_KEM_H
#define KEM_ML_KEM_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* ML-KEM-512 */
#define PQMAGIC_KEM_ml_kem_512_length_public_key      ML_KEM_512_PUBLICKEYBYTES
#define PQMAGIC_KEM_ml_kem_512_length_secret_key      ML_KEM_512_SECRETKEYBYTES
#define PQMAGIC_KEM_ml_kem_512_length_ciphertext      ML_KEM_512_CIPHERTEXTBYTES
#define PQMAGIC_KEM_ml_kem_512_length_shared_secret   ML_KEM_512_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_512_new(void);

/* ML-KEM-768 */
#define PQMAGIC_KEM_ml_kem_768_length_public_key      ML_KEM_768_PUBLICKEYBYTES
#define PQMAGIC_KEM_ml_kem_768_length_secret_key      ML_KEM_768_SECRETKEYBYTES
#define PQMAGIC_KEM_ml_kem_768_length_ciphertext      ML_KEM_768_CIPHERTEXTBYTES
#define PQMAGIC_KEM_ml_kem_768_length_shared_secret   ML_KEM_768_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_768_new(void);

/* ML-KEM-1024 */
#define PQMAGIC_KEM_ml_kem_1024_length_public_key     ML_KEM_1024_PUBLICKEYBYTES
#define PQMAGIC_KEM_ml_kem_1024_length_secret_key     ML_KEM_1024_SECRETKEYBYTES
#define PQMAGIC_KEM_ml_kem_1024_length_ciphertext     ML_KEM_1024_CIPHERTEXTBYTES
#define PQMAGIC_KEM_ml_kem_1024_length_shared_secret  ML_KEM_1024_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_1024_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_ML_KEM_H */
