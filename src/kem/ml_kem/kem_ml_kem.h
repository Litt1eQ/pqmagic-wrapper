/**
 * \file kem_ml_kem.h
 * \brief ML-KEM family algorithm declarations
 */

#ifndef KEM_ML_KEM_H
#define KEM_ML_KEM_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* ML-KEM-512 */
#define PQMAGIC_KEM_ml_kem_512_length_public_key      800
#define PQMAGIC_KEM_ml_kem_512_length_secret_key      1632
#define PQMAGIC_KEM_ml_kem_512_length_ciphertext      768
#define PQMAGIC_KEM_ml_kem_512_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_512_new(void);

/* ML-KEM-768 */
#define PQMAGIC_KEM_ml_kem_768_length_public_key      1184
#define PQMAGIC_KEM_ml_kem_768_length_secret_key      2400
#define PQMAGIC_KEM_ml_kem_768_length_ciphertext      1088
#define PQMAGIC_KEM_ml_kem_768_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_768_new(void);

/* ML-KEM-1024 */
#define PQMAGIC_KEM_ml_kem_1024_length_public_key     1568
#define PQMAGIC_KEM_ml_kem_1024_length_secret_key     3168
#define PQMAGIC_KEM_ml_kem_1024_length_ciphertext     1568
#define PQMAGIC_KEM_ml_kem_1024_length_shared_secret  32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_ml_kem_1024_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_ML_KEM_H */
