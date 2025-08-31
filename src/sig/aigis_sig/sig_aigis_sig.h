/**
 * \file sig_aigis_sig.h
 * \brief Aigis-Sig family algorithm declarations
 */

#ifndef SIG_AIGIS_SIG_H
#define SIG_AIGIS_SIG_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* Aigis-Sig-1 */
#define PQMAGIC_SIG_aigis_sig_1_length_public_key    1056
#define PQMAGIC_SIG_aigis_sig_1_length_secret_key    2448
#define PQMAGIC_SIG_aigis_sig_1_length_signature     1852

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_1_new(void);

/* Aigis-Sig-2 */
#define PQMAGIC_SIG_aigis_sig_2_length_public_key    1312
#define PQMAGIC_SIG_aigis_sig_2_length_secret_key    3088
#define PQMAGIC_SIG_aigis_sig_2_length_signature     2244

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_2_new(void);

/* Aigis-Sig-3 */
#define PQMAGIC_SIG_aigis_sig_3_length_public_key    1568
#define PQMAGIC_SIG_aigis_sig_3_length_secret_key    3728
#define PQMAGIC_SIG_aigis_sig_3_length_signature     2636

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_aigis_sig_3_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_AIGIS_SIG_H */
