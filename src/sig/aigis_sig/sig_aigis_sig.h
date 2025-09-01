/**
 * \file sig_aigis_sig.h
 * \brief Aigis-Sig family algorithm declarations
 */

#ifndef SIG_AIGIS_SIG_H
#define SIG_AIGIS_SIG_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Aigis-Sig-1 */
#define PQMAGIC_SIG_aigis_sig_1_length_public_key    AIGIS_SIG1_PUBLICKEYBYTES
#define PQMAGIC_SIG_aigis_sig_1_length_secret_key    AIGIS_SIG1_SECRETKEYBYTES
#define PQMAGIC_SIG_aigis_sig_1_length_signature     AIGIS_SIG1_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_1_new(void);

/* Aigis-Sig-2 */
#define PQMAGIC_SIG_aigis_sig_2_length_public_key    AIGIS_SIG2_PUBLICKEYBYTES
#define PQMAGIC_SIG_aigis_sig_2_length_secret_key    AIGIS_SIG2_SECRETKEYBYTES
#define PQMAGIC_SIG_aigis_sig_2_length_signature     AIGIS_SIG2_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_2_new(void);

/* Aigis-Sig-3 */
#define PQMAGIC_SIG_aigis_sig_3_length_public_key    AIGIS_SIG3_PUBLICKEYBYTES
#define PQMAGIC_SIG_aigis_sig_3_length_secret_key    AIGIS_SIG3_SECRETKEYBYTES
#define PQMAGIC_SIG_aigis_sig_3_length_signature     AIGIS_SIG3_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_3_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_AIGIS_SIG_H */
