/**
 * \file sig_slh_dsa.h
 * \brief SLH-DSA family algorithm declarations
 */

#ifndef SIG_SLH_DSA_H
#define SIG_SLH_DSA_H

#include "pqmagic_wrapper.h"
#include "pqmagic_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* SLH-DSA-SHA2-128f */
#define PQMAGIC_SIG_slh_dsa_sha2_128f_length_public_key    SLH_DSA_SHA2_128f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_128f_length_secret_key    SLH_DSA_SHA2_128f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_128f_length_signature     SLH_DSA_SHA2_128f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_128f_new(void);

/* SLH-DSA-SHA2-128s */
#define PQMAGIC_SIG_slh_dsa_sha2_128s_length_public_key    SLH_DSA_SHA2_128s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_128s_length_secret_key    SLH_DSA_SHA2_128s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_128s_length_signature     SLH_DSA_SHA2_128s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_128s_new(void);

/* SLH-DSA-SHA2-192f */
#define PQMAGIC_SIG_slh_dsa_sha2_192f_length_public_key    SLH_DSA_SHA2_192f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_192f_length_secret_key    SLH_DSA_SHA2_192f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_192f_length_signature     SLH_DSA_SHA2_192f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_192f_new(void);

/* SLH-DSA-SHA2-192s */
#define PQMAGIC_SIG_slh_dsa_sha2_192s_length_public_key    SLH_DSA_SHA2_192s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_192s_length_secret_key    SLH_DSA_SHA2_192s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_192s_length_signature     SLH_DSA_SHA2_192s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_192s_new(void);

/* SLH-DSA-SHA2-256f */
#define PQMAGIC_SIG_slh_dsa_sha2_256f_length_public_key    SLH_DSA_SHA2_256f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_256f_length_secret_key    SLH_DSA_SHA2_256f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_256f_length_signature     SLH_DSA_SHA2_256f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_256f_new(void);

/* SLH-DSA-SHA2-256s */
#define PQMAGIC_SIG_slh_dsa_sha2_256s_length_public_key    SLH_DSA_SHA2_256s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_256s_length_secret_key    SLH_DSA_SHA2_256s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sha2_256s_length_signature     SLH_DSA_SHA2_256s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sha2_256s_new(void);

/* SLH-DSA-SHAKE-128f */
#define PQMAGIC_SIG_slh_dsa_shake_128f_length_public_key   SLH_DSA_SHAKE_128f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_128f_length_secret_key   SLH_DSA_SHAKE_128f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_128f_length_signature    SLH_DSA_SHAKE_128f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_128f_new(void);

/* SLH-DSA-SHAKE-128s */
#define PQMAGIC_SIG_slh_dsa_shake_128s_length_public_key   SLH_DSA_SHAKE_128s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_128s_length_secret_key   SLH_DSA_SHAKE_128s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_128s_length_signature    SLH_DSA_SHAKE_128s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_128s_new(void);

/* SLH-DSA-SHAKE-192f */
#define PQMAGIC_SIG_slh_dsa_shake_192f_length_public_key   SLH_DSA_SHAKE_192f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_192f_length_secret_key   SLH_DSA_SHAKE_192f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_192f_length_signature    SLH_DSA_SHAKE_192f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_192f_new(void);

/* SLH-DSA-SHAKE-192s */
#define PQMAGIC_SIG_slh_dsa_shake_192s_length_public_key   SLH_DSA_SHAKE_192s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_192s_length_secret_key   SLH_DSA_SHAKE_192s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_192s_length_signature    SLH_DSA_SHAKE_192s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_192s_new(void);

/* SLH-DSA-SHAKE-256f */
#define PQMAGIC_SIG_slh_dsa_shake_256f_length_public_key   SLH_DSA_SHAKE_256f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_256f_length_secret_key   SLH_DSA_SHAKE_256f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_256f_length_signature    SLH_DSA_SHAKE_256f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_256f_new(void);

/* SLH-DSA-SHAKE-256s */
#define PQMAGIC_SIG_slh_dsa_shake_256s_length_public_key   SLH_DSA_SHAKE_256s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_256s_length_secret_key   SLH_DSA_SHAKE_256s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_shake_256s_length_signature    SLH_DSA_SHAKE_256s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_shake_256s_new(void);

/* SLH-DSA-SM3-128f */
#define PQMAGIC_SIG_slh_dsa_sm3_128f_length_public_key     SLH_DSA_SM3_128f_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sm3_128f_length_secret_key     SLH_DSA_SM3_128f_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sm3_128f_length_signature      SLH_DSA_SM3_128f_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sm3_128f_new(void);

/* SLH-DSA-SM3-128s */
#define PQMAGIC_SIG_slh_dsa_sm3_128s_length_public_key     SLH_DSA_SM3_128s_PUBLICKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sm3_128s_length_secret_key     SLH_DSA_SM3_128s_SECRETKEYBYTES
#define PQMAGIC_SIG_slh_dsa_sm3_128s_length_signature      SLH_DSA_SM3_128s_SIGBYTES

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_slh_dsa_sm3_128s_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_SLH_DSA_H */
