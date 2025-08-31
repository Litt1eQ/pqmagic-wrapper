# PQMagic Wrapper API Documentation

## Overview

PQMagic Wrapper is a C library that provides a liboqs-style API for the PQMagic post-quantum cryptographic library. It supports both Key Encapsulation Mechanisms (KEM) and digital signature algorithms, including NIST-standardized algorithms and proprietary Aigis algorithms.

**Version:** 1.0.0  
**License:** MIT  

## Features

- **KEM Algorithms**: ML-KEM (512/768/1024), Kyber (512/768/1024), Aigis-Enc (1/2/3/4)
- **Signature Algorithms**: ML-DSA (44/65/87), Dilithium (2/3/5), SLH-DSA variants, SPHINCS-Alpha, Aigis-Sig (1/2/3)
- **Security Levels**: NIST levels 1, 2, 3, and 5 supported across algorithms
- **Context String Support**: ML-DSA algorithms support context strings for domain separation
- **liboqs-compatible API**: Familiar interface for developers using liboqs

---

## Library Initialization

### Functions

#### `PQMAGIC_init()`
```c
void PQMAGIC_init(void);
```
Initialize the PQMagic library. Must be called before using any other functions.

#### `PQMAGIC_cleanup()`
```c
void PQMAGIC_cleanup(void);
```
Cleanup library resources. Should be called when done using the library.

#### `PQMAGIC_version()`
```c
const char *PQMAGIC_version(void);
```
**Returns:** Library version string (e.g., "1.0.0")

---

## Status Codes

```c
typedef enum {
    PQMAGIC_ERROR = -1,
    PQMAGIC_SUCCESS = 0,
    PQMAGIC_ERROR_INVALID_ALGORITHM = 1,
    PQMAGIC_ERROR_INVALID_PARAMETER = 2,
    PQMAGIC_ERROR_MEMORY_ALLOCATION = 3,
    PQMAGIC_ERROR_NOT_IMPLEMENTED = 4,
} PQMAGIC_STATUS;
```

- **`PQMAGIC_SUCCESS`**: Operation completed successfully
- **`PQMAGIC_ERROR`**: General error
- **`PQMAGIC_ERROR_INVALID_ALGORITHM`**: Unsupported or invalid algorithm name
- **`PQMAGIC_ERROR_INVALID_PARAMETER`**: Invalid parameter passed to function
- **`PQMAGIC_ERROR_MEMORY_ALLOCATION`**: Memory allocation failure
- **`PQMAGIC_ERROR_NOT_IMPLEMENTED`**: Feature not implemented

---

# KEM (Key Encapsulation Mechanism) API

## Supported Algorithms

### ML-KEM (FIPS 203)
- **ML-KEM-512** (`PQMAGIC_KEM_alg_ml_kem_512`): NIST Level 1
- **ML-KEM-768** (`PQMAGIC_KEM_alg_ml_kem_768`): NIST Level 3  
- **ML-KEM-1024** (`PQMAGIC_KEM_alg_ml_kem_1024`): NIST Level 5

### Kyber
- **Kyber512** (`PQMAGIC_KEM_alg_kyber_512`): NIST Level 1
- **Kyber768** (`PQMAGIC_KEM_alg_kyber_768`): NIST Level 3
- **Kyber1024** (`PQMAGIC_KEM_alg_kyber_1024`): NIST Level 5

### Aigis-Enc (Proprietary)
- **Aigis-Enc-1** (`PQMAGIC_KEM_alg_aigis_enc_1`)
- **Aigis-Enc-2** (`PQMAGIC_KEM_alg_aigis_enc_2`) 
- **Aigis-Enc-3** (`PQMAGIC_KEM_alg_aigis_enc_3`)
- **Aigis-Enc-4** (`PQMAGIC_KEM_alg_aigis_enc_4`)

## KEM Structure

```c
typedef struct PQMAGIC_KEM {
    const char *method_name;           // Algorithm name
    const char *alg_version;           // Algorithm version
    uint8_t claimed_nist_level;        // NIST security level
    bool ind_cca;                      // IND-CCA security
    
    // Buffer sizes
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
    
    // Function pointers
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
    PQMAGIC_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
} PQMAGIC_KEM;
```

## KEM Functions

### Algorithm Discovery

#### `PQMAGIC_KEM_alg_count()`
```c
int PQMAGIC_KEM_alg_count(void);
```
**Returns:** Number of available KEM algorithms

#### `PQMAGIC_KEM_alg_identifier()`
```c
const char *PQMAGIC_KEM_alg_identifier(size_t i);
```
**Parameters:**
- `i`: Algorithm index (0 to `PQMAGIC_KEM_alg_count()` - 1)

**Returns:** Algorithm identifier string, or NULL if index is invalid

#### `PQMAGIC_KEM_alg_is_enabled()`
```c
int PQMAGIC_KEM_alg_is_enabled(const char *method_name);
```
**Parameters:**
- `method_name`: Algorithm identifier string

**Returns:** 1 if enabled, 0 otherwise

### Object Management

#### `PQMAGIC_KEM_new()`
```c
PQMAGIC_KEM *PQMAGIC_KEM_new(const char *method_name);
```
Create a new KEM object for the specified algorithm.

**Parameters:**
- `method_name`: Algorithm identifier (e.g., `PQMAGIC_KEM_alg_ml_kem_512`)

**Returns:** KEM object pointer, or NULL on failure

#### `PQMAGIC_KEM_free()`
```c
void PQMAGIC_KEM_free(PQMAGIC_KEM *kem);
```
Free a KEM object and its resources.

**Parameters:**
- `kem`: KEM object to free

### KEM Operations

#### `PQMAGIC_KEM_keypair()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_keypair(const PQMAGIC_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
```
Generate a public/private key pair.

**Parameters:**
- `kem`: KEM object
- `public_key`: Buffer for public key (size: `kem->length_public_key`)
- `secret_key`: Buffer for secret key (size: `kem->length_secret_key`)

**Returns:** `PQMAGIC_STATUS` code

#### `PQMAGIC_KEM_encaps()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_encaps(const PQMAGIC_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
```
Encapsulate a shared secret using the public key.

**Parameters:**
- `kem`: KEM object  
- `ciphertext`: Buffer for ciphertext (size: `kem->length_ciphertext`)
- `shared_secret`: Buffer for shared secret (size: `kem->length_shared_secret`)
- `public_key`: Public key for encapsulation (size: `kem->length_public_key`)

**Returns:** `PQMAGIC_STATUS` code

#### `PQMAGIC_KEM_decaps()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_decaps(const PQMAGIC_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
```
Decapsulate the shared secret using the secret key.

**Parameters:**
- `kem`: KEM object
- `shared_secret`: Buffer for shared secret (size: `kem->length_shared_secret`)
- `ciphertext`: Ciphertext to decapsulate (size: `kem->length_ciphertext`)
- `secret_key`: Secret key for decapsulation (size: `kem->length_secret_key`)

**Returns:** `PQMAGIC_STATUS` code

## KEM Example Usage

```c
#include "pqmagic_wrapper.h"

int main() {
    PQMAGIC_init();
    
    // Create ML-KEM-512 object
    PQMAGIC_KEM *kem = PQMAGIC_KEM_new(PQMAGIC_KEM_alg_ml_kem_512);
    if (!kem) {
        printf("Failed to create KEM object\n");
        return -1;
    }
    
    // Allocate buffers
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret1 = malloc(kem->length_shared_secret);
    uint8_t *shared_secret2 = malloc(kem->length_shared_secret);
    
    // Generate keypair
    PQMAGIC_STATUS status = PQMAGIC_KEM_keypair(kem, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Keypair generation failed\n");
        goto cleanup;
    }
    
    // Encapsulate
    status = PQMAGIC_KEM_encaps(kem, ciphertext, shared_secret1, public_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Encapsulation failed\n");
        goto cleanup;
    }
    
    // Decapsulate  
    status = PQMAGIC_KEM_decaps(kem, shared_secret2, ciphertext, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Decapsulation failed\n");
        goto cleanup;
    }
    
    // Verify shared secrets match
    if (memcmp(shared_secret1, shared_secret2, kem->length_shared_secret) == 0) {
        printf("Success! Shared secrets match.\n");
    }
    
cleanup:
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret1);
    free(shared_secret2);
    PQMAGIC_KEM_free(kem);
    PQMAGIC_cleanup();
    
    return 0;
}
```

---

# Signature API

## Supported Algorithms

### ML-DSA (FIPS 204)
- **ML-DSA-44** (`PQMAGIC_SIG_alg_ml_dsa_44`): NIST Level 2, Context strings supported
- **ML-DSA-65** (`PQMAGIC_SIG_alg_ml_dsa_65`): NIST Level 3, Context strings supported  
- **ML-DSA-87** (`PQMAGIC_SIG_alg_ml_dsa_87`): NIST Level 5, Context strings supported

### Dilithium
- **Dilithium2** (`PQMAGIC_SIG_alg_dilithium_2`): NIST Level 2
- **Dilithium3** (`PQMAGIC_SIG_alg_dilithium_3`): NIST Level 3
- **Dilithium5** (`PQMAGIC_SIG_alg_dilithium_5`): NIST Level 5

### SLH-DSA (FIPS 205)
SHA2 variants:
- **SLH-DSA-SHA2-128f** (`PQMAGIC_SIG_alg_slh_dsa_sha2_128f`): NIST Level 1, Fast
- **SLH-DSA-SHA2-128s** (`PQMAGIC_SIG_alg_slh_dsa_sha2_128s`): NIST Level 1, Small
- **SLH-DSA-SHA2-192f** (`PQMAGIC_SIG_alg_slh_dsa_sha2_192f`): NIST Level 3, Fast
- **SLH-DSA-SHA2-192s** (`PQMAGIC_SIG_alg_slh_dsa_sha2_192s`): NIST Level 3, Small
- **SLH-DSA-SHA2-256f** (`PQMAGIC_SIG_alg_slh_dsa_sha2_256f`): NIST Level 5, Fast
- **SLH-DSA-SHA2-256s** (`PQMAGIC_SIG_alg_slh_dsa_sha2_256s`): NIST Level 5, Small

SHAKE variants:
- **SLH-DSA-SHAKE-128f** (`PQMAGIC_SIG_alg_slh_dsa_shake_128f`): NIST Level 1, Fast
- **SLH-DSA-SHAKE-128s** (`PQMAGIC_SIG_alg_slh_dsa_shake_128s`): NIST Level 1, Small
- **SLH-DSA-SHAKE-192f** (`PQMAGIC_SIG_alg_slh_dsa_shake_192f`): NIST Level 3, Fast
- **SLH-DSA-SHAKE-192s** (`PQMAGIC_SIG_alg_slh_dsa_shake_192s`): NIST Level 3, Small
- **SLH-DSA-SHAKE-256f** (`PQMAGIC_SIG_alg_slh_dsa_shake_256f`): NIST Level 5, Fast
- **SLH-DSA-SHAKE-256s** (`PQMAGIC_SIG_alg_slh_dsa_shake_256s`): NIST Level 5, Small

SM3 variants:
- **SLH-DSA-SM3-128f** (`PQMAGIC_SIG_alg_slh_dsa_sm3_128f`): NIST Level 1, Fast
- **SLH-DSA-SM3-128s** (`PQMAGIC_SIG_alg_slh_dsa_sm3_128s`): NIST Level 1, Small

### SPHINCS-Alpha
Similar variants as SLH-DSA with `sphincs_a_` prefix.

### Aigis-Sig (Proprietary)
- **Aigis-Sig-1** (`PQMAGIC_SIG_alg_aigis_sig_1`): Context strings supported
- **Aigis-Sig-2** (`PQMAGIC_SIG_alg_aigis_sig_2`): Context strings supported
- **Aigis-Sig-3** (`PQMAGIC_SIG_alg_aigis_sig_3`): Context strings supported

## Signature Structure

```c
typedef struct PQMAGIC_SIG {
    const char *method_name;           // Algorithm name
    const char *alg_version;           // Algorithm version  
    uint8_t claimed_nist_level;        // NIST security level
    
    // Security properties
    bool euf_cma;                      // EUF-CMA security
    bool suf_cma;                      // SUF-CMA security  
    bool sig_with_ctx_support;         // Context string support
    
    // Buffer sizes
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
    
    // Function pointers
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*sign_with_ctx_str)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*verify)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
    PQMAGIC_STATUS (*verify_with_ctx_str)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
} PQMAGIC_SIG;
```

## Signature Functions

### Algorithm Discovery

#### `PQMAGIC_SIG_alg_count()`
```c
int PQMAGIC_SIG_alg_count(void);
```
**Returns:** Number of available signature algorithms

#### `PQMAGIC_SIG_alg_identifier()`
```c
const char *PQMAGIC_SIG_alg_identifier(size_t i);
```
**Parameters:**
- `i`: Algorithm index (0 to `PQMAGIC_SIG_alg_count()` - 1)

**Returns:** Algorithm identifier string, or NULL if index is invalid

#### `PQMAGIC_SIG_alg_is_enabled()`
```c
int PQMAGIC_SIG_alg_is_enabled(const char *method_name);
```
**Parameters:**
- `method_name`: Algorithm identifier string

**Returns:** 1 if enabled, 0 otherwise

#### `PQMAGIC_SIG_supports_ctx_str()`
```c
bool PQMAGIC_SIG_supports_ctx_str(const char *alg_name);
```
**Parameters:**
- `alg_name`: Algorithm identifier string

**Returns:** true if algorithm supports context strings

### Object Management

#### `PQMAGIC_SIG_new()`
```c
PQMAGIC_SIG *PQMAGIC_SIG_new(const char *method_name);
```
Create a new signature object for the specified algorithm.

**Parameters:**
- `method_name`: Algorithm identifier (e.g., `PQMAGIC_SIG_alg_ml_dsa_44`)

**Returns:** Signature object pointer, or NULL on failure

#### `PQMAGIC_SIG_free()`
```c
void PQMAGIC_SIG_free(PQMAGIC_SIG *sig);
```
Free a signature object and its resources.

**Parameters:**
- `sig`: Signature object to free

### Signature Operations

#### `PQMAGIC_SIG_keypair()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_keypair(const PQMAGIC_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
```
Generate a public/private key pair.

**Parameters:**
- `sig`: Signature object
- `public_key`: Buffer for public key (size: `sig->length_public_key`)
- `secret_key`: Buffer for secret key (size: `sig->length_secret_key`)

**Returns:** `PQMAGIC_STATUS` code

#### `PQMAGIC_SIG_sign()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_sign(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
```
Sign a message using the secret key.

**Parameters:**
- `sig`: Signature object
- `signature`: Buffer for signature (size: `sig->length_signature`)
- `signature_len`: Input/output parameter for signature length
- `message`: Message to sign
- `message_len`: Length of message
- `secret_key`: Secret key for signing (size: `sig->length_secret_key`)

**Returns:** `PQMAGIC_STATUS` code

#### `PQMAGIC_SIG_sign_with_ctx_str()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_sign_with_ctx_str(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
```
Sign a message with a context string. Only available for algorithms that support context strings.

**Parameters:**
- `sig`: Signature object
- `signature`: Buffer for signature (size: `sig->length_signature`)
- `signature_len`: Input/output parameter for signature length
- `message`: Message to sign
- `message_len`: Length of message
- `ctx_str`: Context string for domain separation
- `ctx_str_len`: Length of context string
- `secret_key`: Secret key for signing (size: `sig->length_secret_key`)

**Returns:** `PQMAGIC_STATUS` code

#### `PQMAGIC_SIG_verify()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_verify(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
```
Verify a signature using the public key.

**Parameters:**
- `sig`: Signature object
- `message`: Original message
- `message_len`: Length of message
- `signature`: Signature to verify  
- `signature_len`: Length of signature
- `public_key`: Public key for verification (size: `sig->length_public_key`)

**Returns:** `PQMAGIC_SUCCESS` if valid, error code otherwise

#### `PQMAGIC_SIG_verify_with_ctx_str()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_verify_with_ctx_str(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
```
Verify a signature with context string. Only available for algorithms that support context strings.

**Parameters:**
- `sig`: Signature object
- `message`: Original message
- `message_len`: Length of message
- `signature`: Signature to verify
- `signature_len`: Length of signature
- `ctx_str`: Context string that was used during signing
- `ctx_str_len`: Length of context string
- `public_key`: Public key for verification (size: `sig->length_public_key`)

**Returns:** `PQMAGIC_SUCCESS` if valid, error code otherwise

## Signature Example Usage

```c
#include "pqmagic_wrapper.h"

int main() {
    PQMAGIC_init();
    
    // Create ML-DSA-44 object
    PQMAGIC_SIG *sig = PQMAGIC_SIG_new(PQMAGIC_SIG_alg_ml_dsa_44);
    if (!sig) {
        printf("Failed to create signature object\n");
        return -1;
    }
    
    // Allocate buffers
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    
    const char *message = "Hello, PQMagic!";
    const char *context = "example_context";
    size_t message_len = strlen(message);
    size_t context_len = strlen(context);
    size_t signature_len;
    
    // Generate keypair
    PQMAGIC_STATUS status = PQMAGIC_SIG_keypair(sig, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("Keypair generation failed\n");
        goto cleanup;
    }
    
    // Sign with context string (ML-DSA supports this)
    if (sig->sig_with_ctx_support) {
        status = PQMAGIC_SIG_sign_with_ctx_str(sig, signature, &signature_len,
                                               (const uint8_t*)message, message_len,
                                               (const uint8_t*)context, context_len,
                                               secret_key);
    } else {
        status = PQMAGIC_SIG_sign(sig, signature, &signature_len,
                                  (const uint8_t*)message, message_len, secret_key);
    }
    
    if (status != PQMAGIC_SUCCESS) {
        printf("Signing failed\n");
        goto cleanup;
    }
    
    // Verify signature
    if (sig->sig_with_ctx_support) {
        status = PQMAGIC_SIG_verify_with_ctx_str(sig, (const uint8_t*)message, message_len,
                                                 signature, signature_len,
                                                 (const uint8_t*)context, context_len,
                                                 public_key);
    } else {
        status = PQMAGIC_SIG_verify(sig, (const uint8_t*)message, message_len,
                                    signature, signature_len, public_key);
    }
    
    if (status == PQMAGIC_SUCCESS) {
        printf("Signature verification successful!\n");
    } else {
        printf("Signature verification failed\n");
    }
    
cleanup:
    free(public_key);
    free(secret_key);
    free(signature);
    PQMAGIC_SIG_free(sig);
    PQMAGIC_cleanup();
    
    return 0;
}
```

---

## Memory Management

**Important:** The caller is responsible for allocating all buffers passed to PQMagic functions. Use the size fields in the KEM/Signature objects to determine required buffer sizes:

- **KEM buffers**: `length_public_key`, `length_secret_key`, `length_ciphertext`, `length_shared_secret`
- **Signature buffers**: `length_public_key`, `length_secret_key`, `length_signature`

**Buffer Ownership:** All buffers passed to functions remain owned by the caller. The library does not allocate or free user buffers.

---

## Thread Safety

The PQMagic Wrapper library is **not thread-safe**. If using in a multi-threaded application, appropriate synchronization mechanisms must be implemented by the application.

---

## Security Considerations

1. **Memory Security**: Clear sensitive key material from memory after use
2. **Randomness**: Ensure the underlying PQMagic library has access to a secure random number generator
3. **Side-Channel Resistance**: The library may be vulnerable to timing and other side-channel attacks
4. **Algorithm Selection**: Choose algorithms appropriate for your security requirements and performance constraints
5. **Context Strings**: When using ML-DSA with context strings, ensure context strings provide proper domain separation

---

## Build Instructions

See the main project documentation for build instructions using CMake:

```bash
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j$(nproc)
./examples/example_kem
./examples/example_sig
```

---

## License

This library is released under the MIT License. See LICENSE file for details.