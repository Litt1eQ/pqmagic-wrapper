/**
 * \file kem_kyber.h  
 * \brief Kyber family algorithm declarations
 */

#ifndef KEM_KYBER_H
#define KEM_KYBER_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Kyber512 */
#define PQMAGIC_KEM_kyber_512_length_public_key      KYBER512_PUBLICKEYBYTES
#define PQMAGIC_KEM_kyber_512_length_secret_key      KYBER512_SECRETKEYBYTES
#define PQMAGIC_KEM_kyber_512_length_ciphertext      KYBER512_CIPHERTEXTBYTES
#define PQMAGIC_KEM_kyber_512_length_shared_secret   KYBER512_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_512_new(void);

/* Kyber768 */
#define PQMAGIC_KEM_kyber_768_length_public_key      KYBER768_PUBLICKEYBYTES
#define PQMAGIC_KEM_kyber_768_length_secret_key      KYBER768_SECRETKEYBYTES
#define PQMAGIC_KEM_kyber_768_length_ciphertext      KYBER768_CIPHERTEXTBYTES
#define PQMAGIC_KEM_kyber_768_length_shared_secret   KYBER768_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_768_new(void);

/* Kyber1024 */
#define PQMAGIC_KEM_kyber_1024_length_public_key     KYBER1024_PUBLICKEYBYTES
#define PQMAGIC_KEM_kyber_1024_length_secret_key     KYBER1024_SECRETKEYBYTES
#define PQMAGIC_KEM_kyber_1024_length_ciphertext     KYBER1024_CIPHERTEXTBYTES
#define PQMAGIC_KEM_kyber_1024_length_shared_secret  KYBER1024_SSBYTES

PQMAGIC_API PQMAGIC_KEM *PQMAGIC_KEM_kyber_1024_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* KEM_KYBER_H */
