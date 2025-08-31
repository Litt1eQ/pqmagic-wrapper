# PQMagic Wrapper API 文档

## 概述

PQMagic Wrapper 是一个 C 语言库，为 PQMagic 后量子密码库提供了类似 liboqs 风格的 API。它支持密钥封装机制（KEM）和数字签名算法，包括 NIST 标准化算法和专有的 Aigis 算法。

**版本：** 1.0.0  
**许可证：** MIT  

## 功能特性

- **KEM 算法**：ML-KEM (512/768/1024)、Kyber (512/768/1024)、Aigis-Enc (1/2/3/4)
- **签名算法**：ML-DSA (44/65/87)、Dilithium (2/3/5)、SLH-DSA 变体、SPHINCS-Alpha、Aigis-Sig (1/2/3)
- **安全级别**：支持 NIST 1、2、3、5 级安全级别
- **上下文字符串支持**：ML-DSA 算法支持用于域分离的上下文字符串
- **liboqs 兼容 API**：为熟悉 liboqs 的开发者提供了熟悉的接口

---

## 库初始化

### 函数

#### `PQMAGIC_init()`
```c
void PQMAGIC_init(void);
```
初始化 PQMagic 库。在使用任何其他函数之前必须调用。

#### `PQMAGIC_cleanup()`
```c
void PQMAGIC_cleanup(void);
```
清理库资源。在完成库的使用后应该调用。

#### `PQMAGIC_version()`
```c
const char *PQMAGIC_version(void);
```
**返回值：** 库版本字符串（例如 "1.0.0"）

---

## 状态码

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

- **`PQMAGIC_SUCCESS`**：操作成功完成
- **`PQMAGIC_ERROR`**：一般错误
- **`PQMAGIC_ERROR_INVALID_ALGORITHM`**：不支持或无效的算法名称
- **`PQMAGIC_ERROR_INVALID_PARAMETER`**：传递给函数的参数无效
- **`PQMAGIC_ERROR_MEMORY_ALLOCATION`**：内存分配失败
- **`PQMAGIC_ERROR_NOT_IMPLEMENTED`**：功能未实现

---

# KEM（密钥封装机制）API

## 支持的算法

### ML-KEM（FIPS 203）
- **ML-KEM-512**（`PQMAGIC_KEM_alg_ml_kem_512`）：NIST 1级安全
- **ML-KEM-768**（`PQMAGIC_KEM_alg_ml_kem_768`）：NIST 3级安全
- **ML-KEM-1024**（`PQMAGIC_KEM_alg_ml_kem_1024`）：NIST 5级安全

### Kyber
- **Kyber512**（`PQMAGIC_KEM_alg_kyber_512`）：NIST 1级安全
- **Kyber768**（`PQMAGIC_KEM_alg_kyber_768`）：NIST 3级安全
- **Kyber1024**（`PQMAGIC_KEM_alg_kyber_1024`）：NIST 5级安全

### Aigis-Enc（专有算法）
- **Aigis-Enc-1**（`PQMAGIC_KEM_alg_aigis_enc_1`）
- **Aigis-Enc-2**（`PQMAGIC_KEM_alg_aigis_enc_2`）
- **Aigis-Enc-3**（`PQMAGIC_KEM_alg_aigis_enc_3`）
- **Aigis-Enc-4**（`PQMAGIC_KEM_alg_aigis_enc_4`）

## KEM 结构体

```c
typedef struct PQMAGIC_KEM {
    const char *method_name;           // 算法名称
    const char *alg_version;           // 算法版本
    uint8_t claimed_nist_level;        // NIST 安全级别
    bool ind_cca;                      // IND-CCA 安全性
    
    // 缓冲区大小
    size_t length_public_key;          // 公钥长度
    size_t length_secret_key;          // 私钥长度
    size_t length_ciphertext;          // 密文长度
    size_t length_shared_secret;       // 共享密钥长度
    
    // 函数指针
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
    PQMAGIC_STATUS (*decaps)(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
} PQMAGIC_KEM;
```

## KEM 函数

### 算法发现

#### `PQMAGIC_KEM_alg_count()`
```c
int PQMAGIC_KEM_alg_count(void);
```
**返回值：** 可用的 KEM 算法数量

#### `PQMAGIC_KEM_alg_identifier()`
```c
const char *PQMAGIC_KEM_alg_identifier(size_t i);
```
**参数：**
- `i`：算法索引（0 到 `PQMAGIC_KEM_alg_count()` - 1）

**返回值：** 算法标识符字符串，如果索引无效则返回 NULL

#### `PQMAGIC_KEM_alg_is_enabled()`
```c
int PQMAGIC_KEM_alg_is_enabled(const char *method_name);
```
**参数：**
- `method_name`：算法标识符字符串

**返回值：** 如果启用返回 1，否则返回 0

### 对象管理

#### `PQMAGIC_KEM_new()`
```c
PQMAGIC_KEM *PQMAGIC_KEM_new(const char *method_name);
```
为指定算法创建新的 KEM 对象。

**参数：**
- `method_name`：算法标识符（例如 `PQMAGIC_KEM_alg_ml_kem_512`）

**返回值：** KEM 对象指针，失败时返回 NULL

#### `PQMAGIC_KEM_free()`
```c
void PQMAGIC_KEM_free(PQMAGIC_KEM *kem);
```
释放 KEM 对象及其资源。

**参数：**
- `kem`：要释放的 KEM 对象

### KEM 操作

#### `PQMAGIC_KEM_keypair()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_keypair(const PQMAGIC_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
```
生成公钥/私钥对。

**参数：**
- `kem`：KEM 对象
- `public_key`：公钥缓冲区（大小：`kem->length_public_key`）
- `secret_key`：私钥缓冲区（大小：`kem->length_secret_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

#### `PQMAGIC_KEM_encaps()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_encaps(const PQMAGIC_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
```
使用公钥封装共享密钥。

**参数：**
- `kem`：KEM 对象
- `ciphertext`：密文缓冲区（大小：`kem->length_ciphertext`）
- `shared_secret`：共享密钥缓冲区（大小：`kem->length_shared_secret`）
- `public_key`：用于封装的公钥（大小：`kem->length_public_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

#### `PQMAGIC_KEM_decaps()`
```c
PQMAGIC_STATUS PQMAGIC_KEM_decaps(const PQMAGIC_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
```
使用私钥解封装共享密钥。

**参数：**
- `kem`：KEM 对象
- `shared_secret`：共享密钥缓冲区（大小：`kem->length_shared_secret`）
- `ciphertext`：要解封装的密文（大小：`kem->length_ciphertext`）
- `secret_key`：用于解封装的私钥（大小：`kem->length_secret_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

## KEM 使用示例

```c
#include "pqmagic_wrapper.h"

int main() {
    PQMAGIC_init();
    
    // 创建 ML-KEM-512 对象
    PQMAGIC_KEM *kem = PQMAGIC_KEM_new(PQMAGIC_KEM_alg_ml_kem_512);
    if (!kem) {
        printf("创建 KEM 对象失败\n");
        return -1;
    }
    
    // 分配缓冲区
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret1 = malloc(kem->length_shared_secret);
    uint8_t *shared_secret2 = malloc(kem->length_shared_secret);
    
    // 生成密钥对
    PQMAGIC_STATUS status = PQMAGIC_KEM_keypair(kem, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("密钥对生成失败\n");
        goto cleanup;
    }
    
    // 封装
    status = PQMAGIC_KEM_encaps(kem, ciphertext, shared_secret1, public_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("封装失败\n");
        goto cleanup;
    }
    
    // 解封装
    status = PQMAGIC_KEM_decaps(kem, shared_secret2, ciphertext, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("解封装失败\n");
        goto cleanup;
    }
    
    // 验证共享密钥匹配
    if (memcmp(shared_secret1, shared_secret2, kem->length_shared_secret) == 0) {
        printf("成功！共享密钥匹配。\n");
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

# 签名 API

## 支持的算法

### ML-DSA（FIPS 204）
- **ML-DSA-44**（`PQMAGIC_SIG_alg_ml_dsa_44`）：NIST 2级安全，支持上下文字符串
- **ML-DSA-65**（`PQMAGIC_SIG_alg_ml_dsa_65`）：NIST 3级安全，支持上下文字符串
- **ML-DSA-87**（`PQMAGIC_SIG_alg_ml_dsa_87`）：NIST 5级安全，支持上下文字符串

### Dilithium
- **Dilithium2**（`PQMAGIC_SIG_alg_dilithium_2`）：NIST 2级安全
- **Dilithium3**（`PQMAGIC_SIG_alg_dilithium_3`）：NIST 3级安全
- **Dilithium5**（`PQMAGIC_SIG_alg_dilithium_5`）：NIST 5级安全

### SLH-DSA（FIPS 205）
SHA2 变体：
- **SLH-DSA-SHA2-128f**（`PQMAGIC_SIG_alg_slh_dsa_sha2_128f`）：NIST 1级安全，快速版
- **SLH-DSA-SHA2-128s**（`PQMAGIC_SIG_alg_slh_dsa_sha2_128s`）：NIST 1级安全，小型版
- **SLH-DSA-SHA2-192f**（`PQMAGIC_SIG_alg_slh_dsa_sha2_192f`）：NIST 3级安全，快速版
- **SLH-DSA-SHA2-192s**（`PQMAGIC_SIG_alg_slh_dsa_sha2_192s`）：NIST 3级安全，小型版
- **SLH-DSA-SHA2-256f**（`PQMAGIC_SIG_alg_slh_dsa_sha2_256f`）：NIST 5级安全，快速版
- **SLH-DSA-SHA2-256s**（`PQMAGIC_SIG_alg_slh_dsa_sha2_256s`）：NIST 5级安全，小型版

SHAKE 变体：
- **SLH-DSA-SHAKE-128f**（`PQMAGIC_SIG_alg_slh_dsa_shake_128f`）：NIST 1级安全，快速版
- **SLH-DSA-SHAKE-128s**（`PQMAGIC_SIG_alg_slh_dsa_shake_128s`）：NIST 1级安全，小型版
- **SLH-DSA-SHAKE-192f**（`PQMAGIC_SIG_alg_slh_dsa_shake_192f`）：NIST 3级安全，快速版
- **SLH-DSA-SHAKE-192s**（`PQMAGIC_SIG_alg_slh_dsa_shake_192s`）：NIST 3级安全，小型版
- **SLH-DSA-SHAKE-256f**（`PQMAGIC_SIG_alg_slh_dsa_shake_256f`）：NIST 5级安全，快速版
- **SLH-DSA-SHAKE-256s**（`PQMAGIC_SIG_alg_slh_dsa_shake_256s`）：NIST 5级安全，小型版

SM3 变体：
- **SLH-DSA-SM3-128f**（`PQMAGIC_SIG_alg_slh_dsa_sm3_128f`）：NIST 1级安全，快速版
- **SLH-DSA-SM3-128s**（`PQMAGIC_SIG_alg_slh_dsa_sm3_128s`）：NIST 1级安全，小型版

### SPHINCS-Alpha
与 SLH-DSA 类似的变体，使用 `sphincs_a_` 前缀。

### Aigis-Sig（专有算法）
- **Aigis-Sig-1**（`PQMAGIC_SIG_alg_aigis_sig_1`）：支持上下文字符串
- **Aigis-Sig-2**（`PQMAGIC_SIG_alg_aigis_sig_2`）：支持上下文字符串
- **Aigis-Sig-3**（`PQMAGIC_SIG_alg_aigis_sig_3`）：支持上下文字符串

## 签名结构体

```c
typedef struct PQMAGIC_SIG {
    const char *method_name;           // 算法名称
    const char *alg_version;           // 算法版本
    uint8_t claimed_nist_level;        // NIST 安全级别
    
    // 安全属性
    bool euf_cma;                      // EUF-CMA 安全性
    bool suf_cma;                      // SUF-CMA 安全性
    bool sig_with_ctx_support;         // 上下文字符串支持
    
    // 缓冲区大小
    size_t length_public_key;          // 公钥长度
    size_t length_secret_key;          // 私钥长度
    size_t length_signature;           // 签名长度
    
    // 函数指针
    PQMAGIC_STATUS (*keypair)(uint8_t *public_key, uint8_t *secret_key);
    PQMAGIC_STATUS (*sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*sign_with_ctx_str)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
    PQMAGIC_STATUS (*verify)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
    PQMAGIC_STATUS (*verify_with_ctx_str)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
} PQMAGIC_SIG;
```

## 签名函数

### 算法发现

#### `PQMAGIC_SIG_alg_count()`
```c
int PQMAGIC_SIG_alg_count(void);
```
**返回值：** 可用的签名算法数量

#### `PQMAGIC_SIG_alg_identifier()`
```c
const char *PQMAGIC_SIG_alg_identifier(size_t i);
```
**参数：**
- `i`：算法索引（0 到 `PQMAGIC_SIG_alg_count()` - 1）

**返回值：** 算法标识符字符串，如果索引无效则返回 NULL

#### `PQMAGIC_SIG_alg_is_enabled()`
```c
int PQMAGIC_SIG_alg_is_enabled(const char *method_name);
```
**参数：**
- `method_name`：算法标识符字符串

**返回值：** 如果启用返回 1，否则返回 0

#### `PQMAGIC_SIG_supports_ctx_str()`
```c
bool PQMAGIC_SIG_supports_ctx_str(const char *alg_name);
```
**参数：**
- `alg_name`：算法标识符字符串

**返回值：** 如果算法支持上下文字符串则返回 true

### 对象管理

#### `PQMAGIC_SIG_new()`
```c
PQMAGIC_SIG *PQMAGIC_SIG_new(const char *method_name);
```
为指定算法创建新的签名对象。

**参数：**
- `method_name`：算法标识符（例如 `PQMAGIC_SIG_alg_ml_dsa_44`）

**返回值：** 签名对象指针，失败时返回 NULL

#### `PQMAGIC_SIG_free()`
```c
void PQMAGIC_SIG_free(PQMAGIC_SIG *sig);
```
释放签名对象及其资源。

**参数：**
- `sig`：要释放的签名对象

### 签名操作

#### `PQMAGIC_SIG_keypair()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_keypair(const PQMAGIC_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
```
生成公钥/私钥对。

**参数：**
- `sig`：签名对象
- `public_key`：公钥缓冲区（大小：`sig->length_public_key`）
- `secret_key`：私钥缓冲区（大小：`sig->length_secret_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

#### `PQMAGIC_SIG_sign()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_sign(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
```
使用私钥对消息进行签名。

**参数：**
- `sig`：签名对象
- `signature`：签名缓冲区（大小：`sig->length_signature`）
- `signature_len`：签名长度的输入/输出参数
- `message`：要签名的消息
- `message_len`：消息长度
- `secret_key`：用于签名的私钥（大小：`sig->length_secret_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

#### `PQMAGIC_SIG_sign_with_ctx_str()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_sign_with_ctx_str(const PQMAGIC_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
```
使用上下文字符串对消息进行签名。仅适用于支持上下文字符串的算法。

**参数：**
- `sig`：签名对象
- `signature`：签名缓冲区（大小：`sig->length_signature`）
- `signature_len`：签名长度的输入/输出参数
- `message`：要签名的消息
- `message_len`：消息长度
- `ctx_str`：用于域分离的上下文字符串
- `ctx_str_len`：上下文字符串长度
- `secret_key`：用于签名的私钥（大小：`sig->length_secret_key`）

**返回值：** `PQMAGIC_STATUS` 状态码

#### `PQMAGIC_SIG_verify()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_verify(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
```
使用公钥验证签名。

**参数：**
- `sig`：签名对象
- `message`：原始消息
- `message_len`：消息长度
- `signature`：要验证的签名
- `signature_len`：签名长度
- `public_key`：用于验证的公钥（大小：`sig->length_public_key`）

**返回值：** 如果有效返回 `PQMAGIC_SUCCESS`，否则返回错误码

#### `PQMAGIC_SIG_verify_with_ctx_str()`
```c
PQMAGIC_STATUS PQMAGIC_SIG_verify_with_ctx_str(const PQMAGIC_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
```
使用上下文字符串验证签名。仅适用于支持上下文字符串的算法。

**参数：**
- `sig`：签名对象
- `message`：原始消息
- `message_len`：消息长度
- `signature`：要验证的签名
- `signature_len`：签名长度
- `ctx_str`：签名时使用的上下文字符串
- `ctx_str_len`：上下文字符串长度
- `public_key`：用于验证的公钥（大小：`sig->length_public_key`）

**返回值：** 如果有效返回 `PQMAGIC_SUCCESS`，否则返回错误码

## 签名使用示例

```c
#include "pqmagic_wrapper.h"

int main() {
    PQMAGIC_init();
    
    // 创建 ML-DSA-44 对象
    PQMAGIC_SIG *sig = PQMAGIC_SIG_new(PQMAGIC_SIG_alg_ml_dsa_44);
    if (!sig) {
        printf("创建签名对象失败\n");
        return -1;
    }
    
    // 分配缓冲区
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    
    const char *message = "你好，PQMagic！";
    const char *context = "示例上下文";
    size_t message_len = strlen(message);
    size_t context_len = strlen(context);
    size_t signature_len;
    
    // 生成密钥对
    PQMAGIC_STATUS status = PQMAGIC_SIG_keypair(sig, public_key, secret_key);
    if (status != PQMAGIC_SUCCESS) {
        printf("密钥对生成失败\n");
        goto cleanup;
    }
    
    // 使用上下文字符串进行签名（ML-DSA 支持此功能）
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
        printf("签名失败\n");
        goto cleanup;
    }
    
    // 验证签名
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
        printf("签名验证成功！\n");
    } else {
        printf("签名验证失败\n");
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

## 内存管理

**重要提示：** 调用者负责分配传递给 PQMagic 函数的所有缓冲区。使用 KEM/签名对象中的大小字段来确定所需的缓冲区大小：

- **KEM 缓冲区**：`length_public_key`、`length_secret_key`、`length_ciphertext`、`length_shared_secret`
- **签名缓冲区**：`length_public_key`、`length_secret_key`、`length_signature`

**缓冲区所有权：** 传递给函数的所有缓冲区仍归调用者所有。库不会分配或释放用户缓冲区。

---

## 线程安全性

PQMagic Wrapper 库**不是线程安全的**。如果在多线程应用程序中使用，应用程序必须实现适当的同步机制。

---

## 安全考虑

1. **内存安全**：使用后应清除内存中的敏感密钥材料
2. **随机性**：确保底层 PQMagic 库能够访问安全的随机数生成器
3. **侧信道抗性**：库可能容易受到时序和其他侧信道攻击
4. **算法选择**：根据安全要求和性能约束选择适当的算法
5. **上下文字符串**：在 ML-DSA 中使用上下文字符串时，确保上下文字符串提供适当的域分离

---

## 构建说明

有关使用 CMake 的构建说明，请参阅主项目文档：

```bash
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j$(nproc)
./examples/example_kem
./examples/example_sig
```

---

## 许可证

该库在 MIT 许可证下发布。详细信息请参见 LICENSE 文件。