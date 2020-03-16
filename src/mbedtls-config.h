#include <limits.h> // Needed by mbed-crypto

#define MBEDTLS_MPI_MAX_SIZE 256

// RSA
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_MD_C
#define MBEDTLS_PKCS1_V21

// SHA
#define MBEDTLS_SHA256_C

// AES-CBC
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
