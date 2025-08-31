/**
 * \file sig_sphincs_alpha.h
 * \brief SPHINCS-Alpha family algorithm declarations
 */

#ifndef SIG_SPHINCS_ALPHA_H
#define SIG_SPHINCS_ALPHA_H

#include "pqmagic_wrapper.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* SPHINCS-A-SHA2-128f */
#define PQMAGIC_SIG_sphincs_a_sha2_128f_length_public_key    32
#define PQMAGIC_SIG_sphincs_a_sha2_128f_length_secret_key    64
#define PQMAGIC_SIG_sphincs_a_sha2_128f_length_signature     16720

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_128f_new(void);

/* SPHINCS-A-SHA2-128s */
#define PQMAGIC_SIG_sphincs_a_sha2_128s_length_public_key    32
#define PQMAGIC_SIG_sphincs_a_sha2_128s_length_secret_key    64
#define PQMAGIC_SIG_sphincs_a_sha2_128s_length_signature     7856

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_128s_new(void);

/* SPHINCS-A-SHA2-192f */
#define PQMAGIC_SIG_sphincs_a_sha2_192f_length_public_key    48
#define PQMAGIC_SIG_sphincs_a_sha2_192f_length_secret_key    96
#define PQMAGIC_SIG_sphincs_a_sha2_192f_length_signature     35032

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_192f_new(void);

/* SPHINCS-A-SHA2-192s */
#define PQMAGIC_SIG_sphincs_a_sha2_192s_length_public_key    48
#define PQMAGIC_SIG_sphincs_a_sha2_192s_length_secret_key    96
#define PQMAGIC_SIG_sphincs_a_sha2_192s_length_signature     16224

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_192s_new(void);

/* SPHINCS-A-SHA2-256f */
#define PQMAGIC_SIG_sphincs_a_sha2_256f_length_public_key    64
#define PQMAGIC_SIG_sphincs_a_sha2_256f_length_secret_key    128
#define PQMAGIC_SIG_sphincs_a_sha2_256f_length_signature     49216

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_256f_new(void);

/* SPHINCS-A-SHA2-256s */
#define PQMAGIC_SIG_sphincs_a_sha2_256s_length_public_key    64
#define PQMAGIC_SIG_sphincs_a_sha2_256s_length_secret_key    128
#define PQMAGIC_SIG_sphincs_a_sha2_256s_length_signature     29792

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sha2_256s_new(void);

/* SPHINCS-A-SHAKE-128f */
#define PQMAGIC_SIG_sphincs_a_shake_128f_length_public_key   32
#define PQMAGIC_SIG_sphincs_a_shake_128f_length_secret_key   64
#define PQMAGIC_SIG_sphincs_a_shake_128f_length_signature    16720

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_128f_new(void);

/* SPHINCS-A-SHAKE-128s */
#define PQMAGIC_SIG_sphincs_a_shake_128s_length_public_key   32
#define PQMAGIC_SIG_sphincs_a_shake_128s_length_secret_key   64
#define PQMAGIC_SIG_sphincs_a_shake_128s_length_signature    7856

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_128s_new(void);

/* SPHINCS-A-SHAKE-192f */
#define PQMAGIC_SIG_sphincs_a_shake_192f_length_public_key   48
#define PQMAGIC_SIG_sphincs_a_shake_192f_length_secret_key   96
#define PQMAGIC_SIG_sphincs_a_shake_192f_length_signature    35032

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_192f_new(void);

/* SPHINCS-A-SHAKE-192s */
#define PQMAGIC_SIG_sphincs_a_shake_192s_length_public_key   48
#define PQMAGIC_SIG_sphincs_a_shake_192s_length_secret_key   96
#define PQMAGIC_SIG_sphincs_a_shake_192s_length_signature    16224

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_192s_new(void);

/* SPHINCS-A-SHAKE-256f */
#define PQMAGIC_SIG_sphincs_a_shake_256f_length_public_key   64
#define PQMAGIC_SIG_sphincs_a_shake_256f_length_secret_key   128
#define PQMAGIC_SIG_sphincs_a_shake_256f_length_signature    49216

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_256f_new(void);

/* SPHINCS-A-SHAKE-256s */
#define PQMAGIC_SIG_sphincs_a_shake_256s_length_public_key   64
#define PQMAGIC_SIG_sphincs_a_shake_256s_length_secret_key   128
#define PQMAGIC_SIG_sphincs_a_shake_256s_length_signature    29792

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_shake_256s_new(void);

/* SPHINCS-A-SM3-128f */
#define PQMAGIC_SIG_sphincs_a_sm3_128f_length_public_key     32
#define PQMAGIC_SIG_sphincs_a_sm3_128f_length_secret_key     64
#define PQMAGIC_SIG_sphincs_a_sm3_128f_length_signature      16720

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sm3_128f_new(void);

/* SPHINCS-A-SM3-128s */
#define PQMAGIC_SIG_sphincs_a_sm3_128s_length_public_key     32
#define PQMAGIC_SIG_sphincs_a_sm3_128s_length_secret_key     64
#define PQMAGIC_SIG_sphincs_a_sm3_128s_length_signature      7856

PQMAGIC_API PQMAGIC_SIG *PQMAGIC_SIG_sphincs_a_sm3_128s_new(void);

#if defined(__cplusplus)
}
#endif

#endif /* SIG_SPHINCS_ALPHA_H */
