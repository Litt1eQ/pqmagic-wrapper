# PQMagic Wrapper

A liboqs-style API wrapper for the PQMagic post-quantum cryptographic library.

## Overview

PQMagic Wrapper provides a clean, standardized API for accessing the high-performance post-quantum cryptographic algorithms in PQMagic. The API is designed to be familiar to developers who have used liboqs, while providing access to PQMagic's superior performance and unique algorithms like Aigis-Enc/Sig and SPHINCS-Alpha.

## Features

- **liboqs-compatible API design**: Easy migration for existing liboqs users
- **High-performance algorithms**: Access to PQMagic's optimized implementations
- **Comprehensive algorithm support**:
  - **KEM algorithms**: ML-KEM, Kyber, Aigis-Enc
  - **Signature algorithms**: ML-DSA, Dilithium, SLH-DSA, SPHINCS-Alpha, Aigis-Sig
- **Context string support**: For algorithms that support it (ML-DSA, Aigis-Sig)
- **Cross-platform**: Windows, macOS, Linux
- **Memory safe**: Proper memory management and cleanup
- **Unit tested**: Comprehensive test suite included

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)

| Algorithm    | Security Level | Standard        | Notes                    |
|--------------|----------------|-----------------|--------------------------|
| ML-KEM-512   | 1              | FIPS 203        | NIST standardized        |
| ML-KEM-768   | 3              | FIPS 203        | NIST standardized        |
| ML-KEM-1024  | 5              | FIPS 203        | NIST standardized        |
| Kyber512     | 1              | Round 3         | Pre-standard             |
| Kyber768     | 3              | Round 3         | Pre-standard             |
| Kyber1024    | 5              | Round 3         | Pre-standard             |
| Aigis-Enc-1  | 1              | Research        | High-performance         |
| Aigis-Enc-2  | 2              | Research        | High-performance         |
| Aigis-Enc-3  | 3              | Research        | High-performance         |
| Aigis-Enc-4  | 5              | Research        | High-performance         |

### Digital Signatures

| Algorithm              | Security Level | Standard     | Context Support | Notes                    |
|-----------------------|----------------|--------------|-----------------|--------------------------|
| ML-DSA-44             | 2              | FIPS 204     | ✓               | NIST standardized        |
| ML-DSA-65             | 3              | FIPS 204     | ✓               | NIST standardized        |
| ML-DSA-87             | 5              | FIPS 204     | ✓               | NIST standardized        |
| Dilithium2            | 2              | Round 3      |                 | Pre-standard             |
| Dilithium3            | 3              | Round 3      |                 | Pre-standard             |
| Dilithium5            | 5              | Round 3      |                 | Pre-standard             |
| SLH-DSA-SHA2-128f     | 1              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHA2-128s     | 1              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SHA2-192f     | 3              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHA2-192s     | 3              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SHA2-256f     | 5              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHA2-256s     | 5              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SHAKE-128f    | 1              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHAKE-128s    | 1              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SHAKE-192f    | 3              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHAKE-192s    | 3              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SHAKE-256f    | 5              | FIPS 205     |                 | Fast variant             |
| SLH-DSA-SHAKE-256s    | 5              | FIPS 205     |                 | Small variant            |
| SLH-DSA-SM3-128f      | 1              | FIPS 205     |                 | Chinese hash function    |
| SLH-DSA-SM3-128s      | 1              | FIPS 205     |                 | Chinese hash function    |
| SPHINCS-A-SHA2-128f   | 1              | Research     |                 | High-performance         |
| SPHINCS-A-SHA2-128s   | 1              | Research     |                 | High-performance         |
| SPHINCS-A-SHA2-192f   | 3              | Research     |                 | High-performance         |
| SPHINCS-A-SHA2-192s   | 3              | Research     |                 | High-performance         |
| SPHINCS-A-SHA2-256f   | 5              | Research     |                 | High-performance         |
| SPHINCS-A-SHA2-256s   | 5              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-128f  | 1              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-128s  | 1              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-192f  | 3              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-192s  | 3              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-256f  | 5              | Research     |                 | High-performance         |
| SPHINCS-A-SHAKE-256s  | 5              | Research     |                 | High-performance         |
| SPHINCS-A-SM3-128f    | 1              | Research     |                 | Chinese hash function    |
| SPHINCS-A-SM3-128s    | 1              | Research     |                 | Chinese hash function    |
| Aigis-Sig-1           | 1              | Research     | ✓               | High-performance         |
| Aigis-Sig-2           | 2              | Research     | ✓               | High-performance         |
| Aigis-Sig-3           | 3              | Research     | ✓               | High-performance         |

## Building

### Prerequisites

- CMake 3.16 or later
- C11-compatible compiler (GCC, Clang, MSVC)
- PQMagic library (included as git submodule)

### Build Steps

```bash
git clone --recursive <repository-url>
cd pqmagic-wrapper
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Build Options

| Option          | Default | Description                    |
|----------------|---------|--------------------------------|
| BUILD_SHARED_LIBS | ON      | Build shared libraries         |
| BUILD_TESTS    | ON      | Build unit tests               |
| BUILD_EXAMPLES | ON      | Build example programs         |

Example with custom options:
```bash
cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=ON ..
```

## Usage

### Basic KEM Example

```c
#include <pqmagic_wrapper.h>

int main() {
    // Initialize library
    PQMAGIC_init();
    
    // Create KEM object
    PQMAGIC_KEM *kem = PQMAGIC_KEM_new(PQMAGIC_KEM_alg_ml_kem_512);
    if (!kem) return -1;
    
    // Allocate memory
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);
    
    // Generate keypair
    PQMAGIC_KEM_keypair(kem, pk, sk);
    
    // Encapsulate
    PQMAGIC_KEM_encaps(kem, ct, ss1, pk);
    
    // Decapsulate
    PQMAGIC_KEM_decaps(kem, ss2, ct, sk);
    
    // Verify shared secrets match
    assert(memcmp(ss1, ss2, kem->length_shared_secret) == 0);
    
    // Cleanup
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    PQMAGIC_KEM_free(kem);
    PQMAGIC_cleanup();
    
    return 0;
}
```

### Basic Signature Example

```c
#include <pqmagic_wrapper.h>

int main() {
    PQMAGIC_init();
    
    // Create signature object
    PQMAGIC_SIG *sig = PQMAGIC_SIG_new(PQMAGIC_SIG_alg_ml_dsa_44);
    if (!sig) return -1;
    
    // Allocate memory
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    
    // Generate keypair
    PQMAGIC_SIG_keypair(sig, pk, sk);
    
    // Sign message
    const char *message = "Hello, PQMagic!";
    size_t sig_len;
    PQMAGIC_SIG_sign(sig, signature, &sig_len, 
                     (uint8_t*)message, strlen(message), sk);
    
    // Verify signature
    PQMAGIC_STATUS result = PQMAGIC_SIG_verify(sig, 
                                               (uint8_t*)message, strlen(message),
                                               signature, sig_len, pk);
    assert(result == PQMAGIC_SUCCESS);
    
    // Cleanup
    free(pk); free(sk); free(signature);
    PQMAGIC_SIG_free(sig);
    PQMAGIC_cleanup();
    
    return 0;
}
```

### Context String Example (ML-DSA)

```c
// Sign with context string
const char *context = "document_v1.0_2024";
PQMAGIC_SIG_sign_with_ctx_str(sig, signature, &sig_len,
                               message, message_len,
                               (uint8_t*)context, strlen(context),
                               secret_key);

// Verify with context string
PQMAGIC_STATUS result = PQMAGIC_SIG_verify_with_ctx_str(sig,
                                                        message, message_len,
                                                        signature, sig_len,
                                                        (uint8_t*)context, strlen(context),
                                                        public_key);
```

## API Reference

### Common Functions

- `PQMAGIC_init()` - Initialize library
- `PQMAGIC_cleanup()` - Cleanup resources
- `PQMAGIC_version()` - Get version string

### KEM Functions

- `PQMAGIC_KEM_new(alg_name)` - Create KEM object
- `PQMAGIC_KEM_keypair(kem, pk, sk)` - Generate keypair
- `PQMAGIC_KEM_encaps(kem, ct, ss, pk)` - Encapsulate
- `PQMAGIC_KEM_decaps(kem, ss, ct, sk)` - Decapsulate
- `PQMAGIC_KEM_free(kem)` - Free KEM object

### Signature Functions

- `PQMAGIC_SIG_new(alg_name)` - Create signature object
- `PQMAGIC_SIG_keypair(sig, pk, sk)` - Generate keypair
- `PQMAGIC_SIG_sign(sig, signature, sig_len, msg, msg_len, sk)` - Sign
- `PQMAGIC_SIG_verify(sig, msg, msg_len, signature, sig_len, pk)` - Verify
- `PQMAGIC_SIG_sign_with_ctx_str(...)` - Sign with context
- `PQMAGIC_SIG_verify_with_ctx_str(...)` - Verify with context
- `PQMAGIC_SIG_free(sig)` - Free signature object

## Testing

Run the test suite:
```bash
cd build
make test
# or directly
./test_pqmagic_wrapper
```

Run examples:
```bash
./examples/example_kem
./examples/example_sig
```

## Performance

PQMagic provides approximately 2x performance improvement over liboqs for most algorithms. Specific benchmarks:

- **ML-KEM-1024**: ~1.7x faster than liboqs
- **ML-DSA-87**: ~2.1x faster than liboqs
- **Aigis algorithms**: Significantly faster than comparable algorithms

See the [official PQMagic benchmarks](https://pqcrypto.dev/benchmarkings/pqmagic/) for detailed performance data.

## Integration

### CMake

```cmake
find_package(PQMagicWrapper REQUIRED)
target_link_libraries(your_target PQMagicWrapper::pqmagic_wrapper)
```

### pkg-config

```bash
gcc $(pkg-config --cflags --libs pqmagic-wrapper) your_program.c
```

## License

Licensed under the MIT License. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Submit a pull request

## Support

- GitHub Issues: [Repository Issues](https://github.com/Litt1eQ/pqmagic-wrapper/issues)
- PQMagic Website: [https://pqcrypto.dev/](https://pqcrypto.dev/)
- Documentation: [API Documentation](doc/API.md)

## References

This project uses and acknowledges the following libraries and references:

### Core Dependencies

- **PQMagic Library**: The core post-quantum cryptographic library providing high-performance implementations
  - Website: [https://pqcrypto.dev/](https://pqcrypto.dev/)
  - Included as git submodule in `external/PQMagic`

### Hash Functions

- **FIPS 202 (SHA-3/SHAKE)**: Implementation of NIST standardized hash functions
  - Used in SHAKE-based SLH-DSA and SPHINCS-Alpha algorithms
  - Source: Keccak implementation in `external/PQMagic/hash/keccak/`

- **SM3**: Chinese national cryptographic hash function
  - Used in SM3-based SLH-DSA and SPHINCS-Alpha algorithms
  - Source: SM3 implementation in `external/PQMagic/hash/sm3/`

### Standards and References

- **FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) Standard
- **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm) Standard  
- **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) Standard
- **NIST PQC Round 3**: Kyber and Dilithium algorithm specifications
- **liboqs**: API design inspiration and compatibility reference
  - Website: [https://openquantumsafe.org/liboqs/](https://openquantumsafe.org/liboqs/)

### Proprietary Algorithms

- **Aigis-Enc/Sig**: High-performance proprietary algorithms developed by the PQMagic team
- **SPHINCS-Alpha**: Enhanced SPHINCS+ implementation with performance optimizations

All algorithm implementations are provided through the PQMagic library and maintain compatibility with their respective standards where applicable.
