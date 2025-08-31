/**
 * \file kem_aigis_enc.h
 * \brief Aigis-Enc family algorithm declarations
 */

#ifndef KEM_AIGIS_ENC_H
#define KEM_AIGIS_ENC_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Aigis-Enc-1 */
#define PQMAGIC_KEM_aigis_enc_1_length_public_key      672
#define PQMAGIC_KEM_aigis_enc_1_length_secret_key      1568
#define PQMAGIC_KEM_aigis_enc_1_length_ciphertext      736
#define PQMAGIC_KEM_aigis_enc_1_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_1_new(void);

/* Aigis-Enc-2 */
#define PQMAGIC_KEM_aigis_enc_2_length_public_key      896
#define PQMAGIC_KEM_aigis_enc_2_length_secret_key      2208
#define PQMAGIC_KEM_aigis_enc_2_length_ciphertext      992
#define PQMAGIC_KEM_aigis_enc_2_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_2_new(void);

/* Aigis-Enc-3 */
#define PQMAGIC_KEM_aigis_enc_3_length_public_key      992
#define PQMAGIC_KEM_aigis_enc_3_length_secret_key      2304
#define PQMAGIC_KEM_aigis_enc_3_length_ciphertext      1056
#define PQMAGIC_KEM_aigis_enc_3_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_3_new(void);

/* Aigis-Enc-4 */
#define PQMAGIC_KEM_aigis_enc_4_length_public_key      1440
#define PQMAGIC_KEM_aigis_enc_4_length_secret_key      3168
#define PQMAGIC_KEM_aigis_enc_4_length_ciphertext      1568
#define PQMAGIC_KEM_aigis_enc_4_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_aigis_enc_4_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_AIGIS_ENC_H */
