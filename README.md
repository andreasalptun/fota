# FOTA - Firmware signing and encryption for over-the-air transfer

FOTA is a lightweight (<50kb) signing and encryption tool/library for embedded systems written in pure c. 

No networking or bootloader in included, making it suitable for most platforms. The general idea is to let a smartphone ask the system for a request token, use it to download an encrypted firmware package and then transfer the package to the system over bluetooth (or similar). The system itself will then decrypt and verify the firmware, before installing it, making sure no secret keys ever leaves the system.

FOTA is licensed under the MIT license. It uses the ARM mbed-crypto for cryptographic functions (https://github.com/ARMmbed/mbed-crypto), which is licensed under the Apache-2.0 license.


## Build the fota-tool

Make sure all submodules are cloned: `git submodule update --init --recursive`

Run `./build` in project root to build the `fota-tool`

Samples keys are used by default. Always create your own keys before using this in production, see the generate keys sections below.


## Create a firmware package

To create a signed and encrypted firmware package, use `fota-tool -m<model> -f<firmware binary>` where _model_ is a string different for each platform (if applicable). Use model `mk1` for testing.

The output is a file called `<model>.fwpk.enc`, which is signed using RSA-PSS and encrypted with the model key using AES-128-CBC.

This file can be uploaded to your server of choice. Google Firebase storage is used here as an example, with code written in Nodejs.

To test locally, copy the package hex (printed to stdout) to `fwpkEnc` buffer in `firebase/functions/index.js`. Make sure firebase emulator is running, see _Firebase_ section below.


## Get a request token

A request token is a hex string used to fetch the encrypted firmware package from the server. It's length will depend on the RSA key size; a 1024 bit key will generate 256 char hex string.

Use `fota-tool -r` to get a request token for testing. Copy and run the curl command printed to download the firmware package. Add the `-l` flag when testing locally.

On system, the request token is generated using the `char* fota_request_token();` function. The return value should be free'd. 

The request token is simply the model key concatenated with the unique key, which is then encrypted with the public encryption key using RSA-OAEP. The data is short enough to be encrypted directly without the need for an intermediary AES key, assuming the RSA key is at least 1024 bits.

The private encryption key is only known to the server, the model key must match and the unique key must be valid (see section _Generate unique keys_ below). This makes it impossible to create a token for a unit without having direct access to the data stored on that particular unit (in code segment and flash storage).


## Unique key encryption layer

When the server gets a request with a valid token, it uses the unique key to add an extra layer of AES-128-CBC encryption before responding. This makes the downloaded firmware package unique for that particular unit and verification will fail on any other unit.


## Verify the firmware package

Use `fota-tool -v <model>.fwpk.enc2` to verify the downloaded firmware package.

On system, the downloaded firmware package must be verified and unwrapped before being installed. This is done using the `buffer_t* fota_verify_package(buffer_t* fwpk_enc2_buf);` function. The `buffer_t` is simply an allocated byte buffer with a length and a read/write position, see `buffer.h`. It should be free'd after use.

The downloaded package (`<model>.fwpk.enc2`) is decrypted in two iterations, first using the unique key and then using the model key. The model identifier is matched and the signature is verified with the public signing key using RSA-PSS. If the function returns null, validation failed.


## Generate unique keys

Each shipped unit must have a unique key. Unique keys are easily generated using `fota-tool -m<model> -g<num-keys>` where _model_ is a string different for each platform (if applicable). Use model `mk1` for testing. 

The unique key can easily be validated on the server without the need for a database, because of its _leading-sha-zeros_ property:

`SHA256(generatorKey + uniqueKey + modelKey + generatorKey) = 000000HEXHASH`

The number of leading zeros is the `generatorDifficulty` = the security level of the key. The generatorKey is only known by the tool (generation) and the server (validation), making it virtually impossible to come up with a unique key that poses the leading zeros property without knowing the generation key.


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


## Generate model and generator keys

Generate random keys for the model key and the generator key using

`openssl rand 32 | xxd -i -c 32`

Copy these random keys to `fota-config.h` and `firebase/function/index.js`


## Firebase

Google Firebase storage is used to store the encrypted firmware package and Firebase functions is used to add an extra layer of encryption to the downloaded firmware package.

See https://firebase.google.com/docs/functions

Deploy

`firebase deploy --only functions`

Run locally (use the `-l` flag when requesting key)

`firebase emulators:start`


## TODO

- Improve random number generators
- Proper AES padding (https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
