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

const modelKeys = {
  'mk1': Buffer.from('519219269431506468c1f899595afe29', 'hex'),
};

// const fwpkEnc = Buffer.from('454e4343bf000000c000000000000000cadf4271948f67b726e39d47804dc5ced632ea3e4bd6f8a41d9ecabbcd84082ee7a88a5a779701cc00f7ee1ca0a9cd94533d9c82fbad72fa3f1ee18596cffd0b9a5d200636d8ec2d276b7c357d0a97fab28262e027980526c877847e5935c0e6b358670f244775d1cbbdf1506772bf16904ebb918089df40a296ab871690e3211c28ced0a0389395db7f72e04e68fc08692b1cf8af09eb709fd1457104b8743a16aa5f3aff5b4ab63a4f7ac2489327d24fdef87208673687aec291524c46259730b3d3fc0f5702eef8bc0487de8545bd', 'hex');
let fwpkEnc = null;

exports.firmware = functions
  .region('europe-west2')
  .https
  .onRequest(async (req, res) => {
    const AES_KEY_LEN = 16;
    if (req.query.model && req.query.token && modelKeys[req.query.model]) {
      const token = crypto.privateDecrypt(privateEncrKey, Buffer.from(req.query.token, 'hex'));
      const modelKey = modelKeys[req.query.model];
      if (modelKey.compare(token, 0, AES_KEY_LEN) == 0) {
        const uniqueKey = token.slice(AES_KEY_LEN);

        // Authenticate unique key
        const authHash = crypto
          .createHash('sha256')
          .update(Buffer.concat([generatorKey, uniqueKey, modelKey, generatorKey]))
          .digest();

        if (Buffer.alloc(generatorDifficulty).compare(authHash, 0, generatorDifficulty) == 0) {
          const iv = crypto.randomBytes(16);
          const cipher = crypto.createCipheriv('aes-128-cbc', uniqueKey, iv);

          try {
            if (!fwpkEnc) {
              let res = await storage
                .bucket('omotion-fota.appspot.com')
                .file(req.query.model + '.fwpk.enc')
                .download();
              fwpkEnc = res[0];
            }

            const padding = Buffer.alloc(16 - (fwpkEnc.length & 0xf));
            let fwpkEnc2 = cipher.update(Buffer.concat([fwpkEnc, padding]));
            cipher.final();

            const header = Buffer.alloc(16);
            header.write("ENCC");
            header.writeUInt32LE(fwpkEnc.length, 4);
            header.writeUInt32LE(fwpkEnc.length + padding.length, 8);
            header.writeUInt32LE(0, 12);

            res.set('content-type', 'application/octet-stream')
            res.send(Buffer.concat([header, iv, fwpkEnc2]));

            return;
          } catch (e) {
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
    } else {
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