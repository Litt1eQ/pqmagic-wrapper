/**
 * \file sig_dilithium.h
 * \brief Dilithium family algorithm declarations
 */

#ifndef SIG_DILITHIUM_H
#define SIG_DILITHIUM_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Dilithium2 */
#define PQMAGIC_SIG_dilithium_2_length_public_key    DILITHIUM2_PUBLICKEYBYTES
#define PQMAGIC_SIG_dilithium_2_length_secret_key    DILITHIUM2_SECRETKEYBYTES
#define PQMAGIC_SIG_dilithium_2_length_signature     DILITHIUM2_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_2_new(void);

/* Dilithium3 */
#define PQMAGIC_SIG_dilithium_3_length_public_key    DILITHIUM3_PUBLICKEYBYTES
#define PQMAGIC_SIG_dilithium_3_length_secret_key    DILITHIUM3_SECRETKEYBYTES
#define PQMAGIC_SIG_dilithium_3_length_signature     DILITHIUM3_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_3_new(void);

/* Dilithium5 */
#define PQMAGIC_SIG_dilithium_5_length_public_key    DILITHIUM5_PUBLICKEYBYTES
#define PQMAGIC_SIG_dilithium_5_length_secret_key    DILITHIUM5_SECRETKEYBYTES
#define PQMAGIC_SIG_dilithium_5_length_signature     DILITHIUM5_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_5_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_DILITHIUM_H */
