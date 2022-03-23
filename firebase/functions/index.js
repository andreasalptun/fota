// MIT License
// 
// Copyright (c) 2020 Andreas Alptun
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const functions = require('firebase-functions');
const crypto = require('crypto');
const unpad_oaep_sha256 = require('./unpad_oaep_sha256');
const {
  Storage
} = require('@google-cloud/storage');

const storage = new Storage({
  // keyFilename: 'omotion-fota-4cdb9a46f95a.json'
});


// TODO Dummy key. Don't store the keys like this in production!!
const privateEncrKey = '\n-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICXQIBAAKBgQDnetwIUOcVJqpH3KXigeJMaNDtgb8JyE3ReIq//n2TQ7onPpHe\n' +
  'mDntbVXtmjQy+2nGI3c/pgQ/851Fq2HUqxJwRJtjCWTyFXbLRI+Pawxgi7K2H6+M\n' +
  'YVat7FryH1NoIc+hg+8V9RP6qv4BuQh9dAd+hhxVfk/gwqRSc/H9wCYYFwIDAQAB\n' +
  'AoGAZnUrD0NABUyn8kbn5eo3kDqUv4u+U0Ylq6H/SBwM2TIRI22+gxg+C6lpb1Hh\n' +
  '6O7/UoRANBv3pZbe9gd1tfxCnDdB0R9gS1jHlmExy5iiP8kLC/2q+4PVMvshWJKP\n' +
  'eUdvV83T2t/xVtsqGGRs99/Uz3Sa/ZP3mHpg2kUIoOAitAECQQD0TGG42VTi08op\n' +
  'UCI4jctAOG8GKsfd/8xNTRPEs3eiAdDRShkR3yA+KT8IZgCPJT7Aw7SXNkQkbgyw\n' +
  'C28KKn53AkEA8pFL2+ZQBW0SibyzkLIMOpQ27PpzDLkZHGdbtRCDtl+K+ANgHot9\n' +
  '08JfcA7SodeGJdYjYgqs+uZPmPMShD97YQJBAJMeaH80Sl1rI8SrYGBka7FaCupQ\n' +
  '2xpDEJrAvxXm6jWjGEjhcaWElFs65Z2+J7oMuPTHJrslT/YMXBGsYQtjOdMCQASe\n' +
  'f7NQT3XK/e9hiInY2iLDb8hTfJ1haPkBft2T0u5GI39VkR8DyQGfUfHwVlJ+qC9Q\n' +
  'RJw5V9HvUNS4zEF4dAECQQCsIsNpOju0KonLVczZoDdXfx7anzqrzsGmyx6uLEjn\n' +
  '0WawYVlFv6QfTJxluiaiGbseYBgl/LwfXg65AKXZTHbv\n' +
  '-----END RSA PRIVATE KEY-----\n';

const generatorKey = Buffer.from('3371ae3bdfc38d0c11d49e223a265547', 'hex');
const generatorDifficulty = 3;

const hmacKey = Buffer.from('8f95ca9fbcda99fe8fd5829ea20fabae6d775b0ec22aa9f1b3ade43b598440f5', 'hex');

const modelKeys = {
  'mk1': Buffer.from('519219269431506468c1f899595afe29', 'hex'),
};

const storagePageSize = 256;

// const fwpkEnc = Buffer.from('454e4343bf000000c000000000000000cadf4271948f67b726e39d47804dc5ced632ea3e4bd6f8a41d9ecabbcd84082ee7a88a5a779701cc00f7ee1ca0a9cd94533d9c82fbad72fa3f1ee18596cffd0b9a5d200636d8ec2d276b7c357d0a97fab28262e027980526c877847e5935c0e6b358670f244775d1cbbdf1506772bf16904ebb918089df40a296ab871690e3211c28ced0a0389395db7f72e04e68fc08692b1cf8af09eb709fd1457104b8743a16aa5f3aff5b4ab63a4f7ac2489327d24fdef87208673687aec291524c46259730b3d3fc0f5702eef8bc0487de8545bd', 'hex');
// const fwpkEnc = Buffer.from('454e4343d00200000000000000000000583d9b50c41bf90cdaf3ec3916279129000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000074b0a692d8932d6ea43afda16e1320e22ffd3daf8a800728bbd9733963faf4eefc701fdd84b11bf2e8d4dc6c87a66d772a2b5b09666d8162c52e8aaf3d1169721eb92f7573c5e0fb54f117bcc2e5a3c528556df397e6084ea0012e8eb4f76b126d114e6af3c6adbd2c602ec86dc68d2700fe12c093af6f8d66bc0f65733e8da796029cc25d65fa86f725dd9d356da8d8a99b2ab128744b22a58c4a00fa2b1cd88349475691da4fc29d4979c66d52515ffbdd06a88d3d4c1950712eef84909163d9914ff12d7912999a5f2886abb35acd2311a441807278e4b9b7cec5423fc7a116888c91369ab2cf305f93710f172f6334e8c15d778c9ae14bf19bfc38d8a45a11b5373654eae665d9cb0a4d100fc719933aa83aa81daac2aaf1ca3dfa67070d22a2d8b00b230346168471cb656f4e51f50ac12c4282eb0d544ead582595167b04596255e9004882ea18f7f71462ca1b6b4fb3d03c6e39b4a54b5359c1ec7fed61e42afec3f4b2f43eac355faacbf108b61ec6f0d78d657df432783ca0e44786c22a676b58c3026712095bcf4296cbb79307f128e43bb9672a6e1ab7837a1f156ffbfb0e9599d407c9f29cd25b0df6fcde5c3b227d81b9340b8bb463f1665ad5e14cfc4c4c33b889bf8849582b8b27b02c2a79036bace7784f9e6f698d3d5f110e6cee406321201c3f3596912a7c566fbfcf20c30a18a60ab925e8d7bf44f507d12ce29765e445f4843ac53b850fe048668b237a83326f3c2bc8c3634db59b066ee61a3e6f426785bcd76b8139d719bc2e4d224247c98dd4267e336cfb5bf6f53c1dc7d081fc939aa8f3a84e0d668b8dcb5328c7b12fef6da19159311f78b4e782407ad2890e734eb6ae05d589a38b3a5d25e67e0299858ceb0e2248afe519d870fd17831c76191c1708aa35033921c5107162a37f32a82e1bb99d02d63946bc0f446cbd144492ed073be52a5b4b7daab2165b12b2d0d3403ed33cd73585cb47d1d27221d814f6e2c03653ce438e9c55', 'hex');
let fwpkEnc = null;

exports.firmware = functions
  .region('europe-west2')
  .https
  .onRequest(async (req, res) => {
    const AES_KEY_LEN = 16;
    if (req.query.model && req.query.token && modelKeys[req.query.model]) {

      let token;
      try {
        token = unpad_oaep_sha256(crypto.privateDecrypt({
          key: privateEncrKey,
          padding: crypto.constants.RSA_NO_PADDING
        }, Buffer.from(req.query.token, 'hex')), "fota-request-token");
      }
      catch (e) {
        console.error(e.message);
      }

      const modelKey = modelKeys[req.query.model];
      if (Buffer.isBuffer(token) && modelKey.compare(token, 0, AES_KEY_LEN) == 0) {
        const uniqueKey = token.slice(AES_KEY_LEN, 2 * AES_KEY_LEN);

        // Authenticate unique key
        const authHash = crypto
          .createHash('sha256')
          .update(Buffer.concat([generatorKey, uniqueKey, modelKey, generatorKey]))
          .digest();

        if (Buffer.alloc(generatorDifficulty).compare(authHash, 0, generatorDifficulty) == 0) {

          // Get aux data
          const auxData = token.slice(2 * AES_KEY_LEN);

          // TODO use aux data
          //console.log(auxData.toString());

          try {
            if (!fwpkEnc) {
              let res = await storage
                .bucket('omotion-fota.appspot.com')
                .file(req.query.model + '.fwpk.enc')
                .download();
              fwpkEnc = res[0];
            }

            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-128-cbc', uniqueKey, iv);

            const fwpkEncEncrypted = Buffer.concat([cipher.update(fwpkEnc), cipher.final()]);

            if (fwpkEncEncrypted.length < 3 * storagePageSize) {
              throw new Error('Package is corrupt');
            }

            const fwpkEnc2 = Buffer.alloc(storagePageSize + fwpkEncEncrypted.length);
            fwpkEnc2.write("ENCC");
            fwpkEnc2.writeUInt32LE(fwpkEnc.length, 4);

            iv.copy(fwpkEnc2, 16);
            fwpkEncEncrypted.copy(fwpkEnc2, storagePageSize);

            // Calculate hmac on the first four storage pages (headers + signature)
            const hmac = crypto.createHmac('sha256', hmacKey);
            hmac.update(fwpkEnc2.slice(0, 4 * storagePageSize));
            hmac.digest().copy(fwpkEnc2, 32);

            res.set('content-type', 'application/octet-stream')
            res.send(fwpkEnc2);

            return;
          }
          catch (e) {
            console.error(e.message);
            res.sendStatus(
              e.response &&
              typeof(e.response.statusCode) === 'number' &&
              e.response.statusCode || 500);
            return;
          }
        }
      }
      res.sendStatus(403);
    }
    else {
      res.sendStatus(400);
    }
  });

exports.notifyUsers = functions
  .region('europe-west2')
  .storage
  .object()
  .onFinalize(async (object) => {
    console.log('New object ' + object.bucket + ', ' + object.name + ', ' + object.contentType);
    // TODO check file and send push notifications
  });
