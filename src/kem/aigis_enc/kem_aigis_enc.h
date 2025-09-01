/**
 * \file kem_aigis_enc.h
 * \brief Aigis-Enc family algorithm declarations
 */

#ifndef KEM_AIGIS_ENC_H
#define KEM_AIGIS_ENC_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Aigis-Enc-1 */
#define PQMAGIC_KEM_aigis_enc_1_length_public_key      AIGIS_ENC_1_PUBLICKEYBYTES
#define PQMAGIC_KEM_aigis_enc_1_length_secret_key      AIGIS_ENC_1_SECRETKEYBYTES
#define PQMAGIC_KEM_aigis_enc_1_length_ciphertext      AIGIS_ENC_1_CIPHERTEXTBYTES
#define PQMAGIC_KEM_aigis_enc_1_length_shared_secret   AIGIS_ENC_1_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_1_new(void);

/* Aigis-Enc-2 */
#define PQMAGIC_KEM_aigis_enc_2_length_public_key      AIGIS_ENC_2_PUBLICKEYBYTES
#define PQMAGIC_KEM_aigis_enc_2_length_secret_key      AIGIS_ENC_2_SECRETKEYBYTES
#define PQMAGIC_KEM_aigis_enc_2_length_ciphertext      AIGIS_ENC_2_CIPHERTEXTBYTES
#define PQMAGIC_KEM_aigis_enc_2_length_shared_secret   AIGIS_ENC_2_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_2_new(void);

/* Aigis-Enc-3 */
#define PQMAGIC_KEM_aigis_enc_3_length_public_key      AIGIS_ENC_3_PUBLICKEYBYTES
#define PQMAGIC_KEM_aigis_enc_3_length_secret_key      AIGIS_ENC_3_SECRETKEYBYTES
#define PQMAGIC_KEM_aigis_enc_3_length_ciphertext      AIGIS_ENC_3_CIPHERTEXTBYTES
#define PQMAGIC_KEM_aigis_enc_3_length_shared_secret   AIGIS_ENC_3_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_3_new(void);

/* Aigis-Enc-4 */
#define PQMAGIC_KEM_aigis_enc_4_length_public_key      AIGIS_ENC_4_PUBLICKEYBYTES
#define PQMAGIC_KEM_aigis_enc_4_length_secret_key      AIGIS_ENC_4_SECRETKEYBYTES
#define PQMAGIC_KEM_aigis_enc_4_length_ciphertext      AIGIS_ENC_4_CIPHERTEXTBYTES
#define PQMAGIC_KEM_aigis_enc_4_length_shared_secret   AIGIS_ENC_4_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_4_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_AIGIS_ENC_H */
