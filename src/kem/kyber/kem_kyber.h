/**
 * \file kem_kyber.h  
 * \brief Kyber family algorithm declarations
 */

#ifndef KEM_KYBER_H
#define KEM_KYBER_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Kyber512 */
#define PQMAGIC_KEM_kyber_512_length_public_key      800
#define PQMAGIC_KEM_kyber_512_length_secret_key      1632
#define PQMAGIC_KEM_kyber_512_length_ciphertext      768
#define PQMAGIC_KEM_kyber_512_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_512_new(void);

/* Kyber768 */
#define PQMAGIC_KEM_kyber_768_length_public_key      1184
#define PQMAGIC_KEM_kyber_768_length_secret_key      2400
#define PQMAGIC_KEM_kyber_768_length_ciphertext      1088
#define PQMAGIC_KEM_kyber_768_length_shared_secret   32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_768_new(void);

/* Kyber1024 */
#define PQMAGIC_KEM_kyber_1024_length_public_key     1568
#define PQMAGIC_KEM_kyber_1024_length_secret_key     3168
#define PQMAGIC_KEM_kyber_1024_length_ciphertext     1568
#define PQMAGIC_KEM_kyber_1024_length_shared_secret  32

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_1024_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_KYBER_H */
