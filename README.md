# FOTA - Firmware signing and encryption for over-the-air transfer

FOTA is a lightweight (&lt;50kb) signing and encryption tool/library for embedded systems, written in pure c. 

No networking or bootloader is included, making it suitable for most platforms. The general idea is to let a smartphone app fetch a request token from the embedded system, use it to download an encrypted and signed firmware package and then transfer the package back to the system over bluetooth (or similar). The system itself will then decrypt and verify the firmware before installing it.

The crypto algorithms used are RSA-PSS for firmware signing, AES-128 for package encryption and RSA-OAEP for token encryption. The hashing algorithm used for signature and HMAC is SHA-256.

FOTA is licensed under the MIT license. It depends on the ARM mbed-crypto for cryptographic functions (<https://github.com/ARMmbed/mbed-crypto>), which is licensed under the Apache-2.0 license.

The FOTA client doesn't allocate any data itself, only stack memory is used. The mbed-crypto library does allocate some memory on the heap, but uses a small RAM footprint.

## Build the fota-tool

Make sure all submodules are cloned: `git submodule update --init --recursive`

Run `./build` in project root to build the `fota-tool`

Samples keys are used by default. Always create your own keys before using this in production, see the generate keys sections below.

## Create a firmware package

To create a signed and encrypted firmware package, use `fota-tool -m<model> -f<firmware binary>` where _model_ is a string different for each platform (if applicable). Use model `mk1` for testing. Add a `-2` option to create a file ready for verification and installing, bypassing the server. Use this for testing only!

The output is a file called `<model>.fwpk.enc`, which is signed using RSA-PSS and encrypted with the model key using AES-128-CBC.

This file can be uploaded to your server of choice. Google Firebase storage is used here as an example, with code written in Nodejs.

To test locally, copy the package hex (printed to stdout if uncommented in fota-tool main) to `fwpkEnc` buffer in `firebase/functions/index.js`. Make sure firebase emulator is running, see _Firebase_ section below.

## Get a request token

A request token is a hex string used to fetch the encrypted firmware package from the server. A new string will be generated each time. It's length will depend on the RSA key size; a 1024 bit key will generate 128 byte token. 

Use `fota-tool -r` to get a request token for testing. Copy and run the curl command printed to download the firmware package. Add the `-l` flag when testing locally.

On system, the request token is generated using the `int fota_request_token(fota_token_t token)` function. It must be encoded to hex before used in the server request query string.

The request token is simply the model key concatenated with the unique key, which is then encrypted with the public encryption key using RSA-OAEP. The data is short enough to be encrypted directly without the need for an intermediary AES key, assuming the RSA key is at least 1024 bits.

Extra data can be embedded in the encrypted token. This can be any data needed on the server, for example a serial number or other device info. The available length depends on the size of the RSA key. See `fotai_get_aux_request_data`.

The private encryption key is only known to the server, the model key must match and the unique key must be valid (see section _Generate unique keys_ below). This makes it impossible to create a token for a unit without having direct access to the data stored on that particular unit (in code segment and flash storage).

## Unique key encryption layer

When the server gets a request with a valid token, it uses the unique key to add an extra layer of AES-128-CBC encryption and adds a HMAC before responding. This makes the downloaded firmware package unique for that particular unit and verification will fail on any other unit.

## Verify the firmware package

Use `fota-tool -v <model>.fwpk.enc2` to verify the downloaded firmware package.

On system, the downloaded firmware package must be verified before being installed. This is done using the `int fota_verify_package(fota_sha_hash_t firmware_hash)` function. After successful verification, the firmware can be installed using the function `int fota_install_package()`. 

The firmware hash is written to the provided `firmware_hash` buffer during verification. This can be used to check the integrity of the installed data after writing it to flash memory. For more information, see the API and integration section below.

The HMAC of the downloaded package (`<model>.fwpk.enc2`) is first verified, then the package is decrypted in two iterations, first using the unique key and then using the model key. The model identifier is matched and the signature is verified with the public signing key using RSA-PSS.

## Generate unique keys

Each shipped unit must have a unique key. Unique keys are easily generated using `fota-tool -m<model> -g<num-keys>` where _model_ is a string matching the platform. Use model `mk1` for testing. 

The unique key can easily be validated on the server without the need for a database, because of its _leading-hash-zeros_ property:

`SHA256(generatorKey + uniqueKey + modelKey + generatorKey) = 000000HEXHASH`

The number of leading zeros is the `generatorDifficulty` = the security level of the key. The generatorKey is only known to the tool (for generation) and to the server (for validation), making it virtually impossible to come up with a unique key that poses the leading zeros property, without knowing the generation key.

## Generate RSA keys

Generate two new key pairs, one for encryption and one for signing. Use 2048 bits or larger in production.

`openssl genrsa -out private.pem 1024`

Extract the key components

`openssl rsa -in private.pem -text -noout > private.txt`

Open `private.txt` in a text editor and remove everything except the modulus section. Remove the first 0 byte and make sure the size is correct (should be RSA_KEY_BITSIZE/8 bytes).

Convert the hex into binary

`xxd -r -p private.txt private.bin`

Store the data in this file in a suitable memory location, preferably an external flash memory.

For testing purposes, the binary can be converted to a c-include
`xxd -i private.bin private.h`

Copy the private exponent from the `private.txt` file to `fota-config.h` and reformat it into a hex string.

Copy the private encryption key pem to firebase/functions/index.js. Note: the private key should not be stored in clear text like in the example.

## Generate hmac, model and generator keys

Generate random keys for the model key and the generator key using

`openssl rand 32 | xxd -i -c 32`

Use the same function for the hmac key but change the size to 64.

Copy these random keys to `fota-config.h` and `firebase/function/index.js`

## API & Integration

```c
// Definitions
//

// Errors
#define FOTA_NO_ERROR                  0
#define FOTA_ERROR_BAD_ARGUMENTS       1
#define FOTA_ERROR_BAD_MODEL           2
#define FOTA_ERROR_DATA_MALFORMED      3
#define FOTA_ERROR_VERIFICATION_FAILED 4
#define FOTA_ERROR_READ_FAILED         5
#define FOTA_ERROR_WRITE_FAILED        6
#define FOTA_ERROR_AES_DECRYPT_FAILED  7

// Type for fotai_get_public_key function
#define FOTA_PUBLIC_KEY_TYPE_SIGNING    0
#define FOTA_PUBLIC_KEY_TYPE_ENCRYPTION 1

// Typedefs
typedef uint8_t fota_token_t[FOTA_RSA_KEY_BITSIZE/8];
typedef uint8_t fota_rsa_key_t[FOTA_RSA_KEY_BITSIZE/8];
typedef uint8_t fota_aes_key_t[FOTA_AES_KEY_BITSIZE/8];
typedef uint8_t fota_aes_iv_t[16];
typedef uint8_t fota_sha_hash_t[FOTA_SHA_HASH_BITSIZE/8];


// FOTA API
//

// Returns a static model id string, do not free
const char* fota_model_id();

// Generates a request token for downloading the firmware package from server.
// The generated token in placed in the fota_token_t buffer.
// Returns FOTA_NO_ERROR if the request token was successfully generated.
int fota_request_token(fota_token_t token);

// Decrypt and verify package signature.
// Uses fotai_read_storage_page to read pages from the memory where the downloaded
// firmware package is stored. Uses fotai_aes_* for AES decryption.
// No data is modified during this process.
// The firmware hash is written to the provided firmware_hash buffer if verification
// is successful. This can be used to check the integrity of the installed data 
// after writing it to flash memory. The hash algorithm used is SHA-256.
// Returns FOTA_NO_ERROR if the firmware signature is valid.
int fota_verify_package(fota_sha_hash_t firmware_hash);

// Decrypt and install the package.
// Uses fotai_read_storage_page to read pages from the memory where the downloaded
// firmware package is stored. Uses fotai_aes_* for AES decryption.
// Uses fotai_write_firmware_page to write pages to destination firmware flash memory.
// This function does not check the signature. Call fota_verify_package and
// check the result before installing.
// Returns FOTA_NO_ERROR if the firmware was successfully installed.
int fota_install_package();


// FOTA integration functions, must be supplied by the system. Example integration in fota-integration.c
//

// Read a single memory page from where the downloaded firmware package is stored,
// usually an external flash chip. The size of a page is defined by FOTA_STORAGE_PAGE_SIZE
// and the provided buffer will be large enough to fit a page. Page 0 is expected to be
// the first page of the firmware package, starting at byte 0.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_READ_FAILED.
extern int fotai_read_storage_page(uint8_t* buf, int page);

// Write a single memory page to where the firmware is stored, usually the internal
// flash memory. The size of a page is defined by FOTA_INSTALL_PAGE_SIZE. Page 0 is
// the first page of the decrypted firmware, starting at byte 0. The len parameter
// is FOTA_INSTALL_PAGE_SIZE except for the last written page, where it might be less.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_WRITE_FAILED.
extern int fotai_write_firmware_page(uint8_t* buf, int page, int len);

// Read the unique key from flash memory into the provided buffer.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_READ_FAILED.
extern int fotai_get_unique_key(fota_aes_key_t unique_key);

// Read a public key (rsa key modulo) from flash memory into the provided buffer.
// The type parameter is either FOTA_PUBLIC_KEY_TYPE_SIGNING or FOTA_PUBLIC_KEY_TYPE_ENCRYPTION.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_READ_FAILED.
extern int fotai_get_public_key(fota_rsa_key_t public_key, int type);

// Append auxillary data to the token, which will be encrypted together with the keys
// using RSA-OAEP. This can be any data needed on the server, for example a serial number
// or other device info. The max length depends on the size of the RSA key.
extern void fotai_get_aux_request_data(uint8_t* buf, int max_len);

// Generate len random bytes into the provided buffer. On system the random bytes are
// used for RSA-OAEP padding generation and should preferably be cryptographically secure.
extern void fotai_generate_random(uint8_t* buf, int len);

// Initialize AES-128-CBC decryption with the provided decryption key. If the decryption
// requires a context it can be set by dereferencing ctx and setting it as a void pointer.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_AES_DECRYPT_FAILED.
extern int fotai_aes_decrypt_init(fota_aes_key_t key, void** ctx);

// Decrypt a block of size len bytes from in to out, using the provided initialization
// vector. The initialization vector will be modified in each call, allowing this function
// to be called multiple times for consecutive blocks. The block len is a multiple of
// of 16 bytes. If a context is provided in the init function, it will be accessible
// from the ctx pointer.
// Should return FOTA_NO_ERROR on success or FOTA_ERROR_AES_DECRYPT_FAILED.
extern int fotai_aes_decrypt_block(fota_aes_key_t key, uint8_t* in, uint8_t* out, int len, fota_aes_iv_t iv, void* ctx);

// Releases memory allocated by the init function, if necessary. If a context is provided
// in the init function, it will be accessible from the ctx pointer.
extern void fotai_aes_decrypt_free(void* ctx);
```

## Firebase

Google Firebase storage is used to store the encrypted firmware package and Firebase functions is used to add an extra layer of encryption to the downloaded firmware package.

See <https://firebase.google.com/docs/functions>

Deploy

`firebase deploy --only functions`

Run locally (use the `-l` flag when requesting key)

`firebase emulators:start`

