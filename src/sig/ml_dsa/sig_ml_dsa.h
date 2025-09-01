/**
 * \file sig_ml_dsa.h
 * \brief ML-DSA family algorithm declarations
 */

#ifndef SIG_ML_DSA_H
#define SIG_ML_DSA_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* ML-DSA-44 */
#define PQMAGIC_SIG_ml_dsa_44_length_public_key    ML_DSA_44_PUBLICKEYBYTES
#define PQMAGIC_SIG_ml_dsa_44_length_secret_key    ML_DSA_44_SECRETKEYBYTES
#define PQMAGIC_SIG_ml_dsa_44_length_signature     ML_DSA_44_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_44_new(void);

/* ML-DSA-65 */
#define PQMAGIC_SIG_ml_dsa_65_length_public_key    ML_DSA_65_PUBLICKEYBYTES
#define PQMAGIC_SIG_ml_dsa_65_length_secret_key    ML_DSA_65_SECRETKEYBYTES
#define PQMAGIC_SIG_ml_dsa_65_length_signature     ML_DSA_65_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_65_new(void);

/* ML-DSA-87 */
#define PQMAGIC_SIG_ml_dsa_87_length_public_key    ML_DSA_87_PUBLICKEYBYTES
#define PQMAGIC_SIG_ml_dsa_87_length_secret_key    ML_DSA_87_SECRETKEYBYTES
#define PQMAGIC_SIG_ml_dsa_87_length_signature     ML_DSA_87_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_ml_dsa_87_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_ML_DSA_H */
