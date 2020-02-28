# FOTA - firmware updater


## Generate keys

Generate new key pair (use 2048 bits or larger in production)

`openssl genrsa -out private.pem 1024`

Get the private key in binary format

`openssl rsa -in private.pem -outform DER -out private.der`

Get the public key in binary format

`openssl rsa -in private.pem -outform DER -pubout -out public.der`


## Firebase

https://firebase.google.com/docs/functions

Deploy

`firebase deploy --only functions`

Run locally (use the -l flag when requesting key)

`firebase emulators:start`


## Build

Apply the patch in libtomcrypt

Run make in tomsfastmath and in libtomcrypt

Run ./build in root


## Tool usage

`fota-tool [-m model] [-f firmware] [-r request key] [-v verify] [-l local url]`

Step 1. Create a firmware package

 `fota-tool -m mk1 -f firmware.bin`

Step 2a (live). Upload mk1.fwpk.enc to firebase storage

https://console.firebase.google.com/u/0/project/xxx-fota/storage/xxx-fota.appspot.com/files

Step 2b (local). Copy the package hex to `fwpkEnc` in firebase/functions/index.js. Make sure firebase emulator is running.

Step 3. Get a request key (use -l if local)

`fota-tool -r`

Step 4. Run the curl command printed in step 3

Example: `curl http://localhost:5001/omotion-fota/europe-west2/firmware?model=mk1&key=493040a084b5e55a6bbad18d29ac7ff8c0b1e404f97bc5a47f6ec6f89c09d17fdf924a0efba5f21191508fa321e5ca70123dea0534d93231fc771535af28c6bd429827b7ae2ea05f9e94957f5c9f15b57093c3d1901054b24d1b6cfcbdc86617211e06a6a90ef80043482249d472d3d99105c913a22e5f9e444450821cbb41ec -v --output mk1.fwpk.enc2
`

Step 5. Verify the package

`fota-tool -v mk1.fwpk.enc2`

## TODO

Clean up buffer.c
