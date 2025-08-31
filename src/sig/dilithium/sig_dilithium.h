/**
 * \file sig_dilithium.h
 * \brief Dilithium family algorithm declarations
 */

#ifndef SIG_DILITHIUM_H
#define SIG_DILITHIUM_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Dilithium2 */
#define PQMAGIC_SIG_dilithium_2_length_public_key    1312
#define PQMAGIC_SIG_dilithium_2_length_secret_key    2528
#define PQMAGIC_SIG_dilithium_2_length_signature     2420

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_2_new(void);

/* Dilithium3 */
#define PQMAGIC_SIG_dilithium_3_length_public_key    1952
#define PQMAGIC_SIG_dilithium_3_length_secret_key    4000
#define PQMAGIC_SIG_dilithium_3_length_signature     3293

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_3_new(void);

/* Dilithium5 */
#define PQMAGIC_SIG_dilithium_5_length_public_key    2592
#define PQMAGIC_SIG_dilithium_5_length_secret_key    4864
#define PQMAGIC_SIG_dilithium_5_length_signature     4595

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_dilithium_5_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_DILITHIUM_H */
