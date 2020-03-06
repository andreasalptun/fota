#include <limits.h> // Needed by mbed-crypto

// RSA
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C

// SHA256
#define MBEDTLS_SHA256_C

// AES-CBC
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
