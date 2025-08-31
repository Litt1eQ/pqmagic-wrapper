/**
 * \file sig_ml_dsa.h
 * \brief ML-DSA family algorithm declarations
 */

#ifndef SIG_ML_DSA_H
#define SIG_ML_DSA_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* ML-DSA-44 */
#define PQMAGIC_SIG_ml_dsa_44_length_public_key    1312
#define PQMAGIC_SIG_ml_dsa_44_length_secret_key    2560
#define PQMAGIC_SIG_ml_dsa_44_length_signature     2420

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_44_new(void);

/* ML-DSA-65 */
#define PQMAGIC_SIG_ml_dsa_65_length_public_key    1952
#define PQMAGIC_SIG_ml_dsa_65_length_secret_key    4032
#define PQMAGIC_SIG_ml_dsa_65_length_signature     3309

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_65_new(void);

/* ML-DSA-87 */
#define PQMAGIC_SIG_ml_dsa_87_length_public_key    2592
#define PQMAGIC_SIG_ml_dsa_87_length_secret_key    4896
#define PQMAGIC_SIG_ml_dsa_87_length_signature     4627

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_87_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_ML_DSA_H */
