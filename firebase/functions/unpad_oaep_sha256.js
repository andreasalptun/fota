// Copyright (c) 2014 rzcoder
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
// associated documentation files (the "Software"), to deal in the Software without restriction, including 
// without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to 
// the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial 
// portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT 
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const crypto = require('crypto');

/*
 * OAEP Mask Generation Function 1
 * Generates a buffer full of pseudorandom bytes given seed and maskLength.
 * Giving the same seed, maskLength, and hashFunction will result in the same exact byte values in the buffer.
 *
 * https://tools.ietf.org/html/rfc3447#appendix-B.2.1
 *
 * Parameters:
 * seed			[Buffer]	The pseudo random seed for this function
 * maskLength	[int]		The length of the output
 */
function genmask_oaep_sha256(seed, maskLength) {
  var hLen = 32;
  var count = Math.ceil(maskLength / hLen);
  var T = Buffer.alloc(hLen * count);
  var c = Buffer.alloc(4);
  for (var i = 0; i < count; ++i) {
    var hash = crypto.createHash('sha256');
    hash.update(seed);
    c.writeUInt32BE(i, 0);
    hash.update(c);
    hash.digest().copy(T, i * hLen);
  }
  return T.slice(0, maskLength);
};

/**
 * Unpad input
 * alg: PKCS1_OAEP
 *
 * Note: This method works within the buffer given and modifies the values. It also returns a slice of the EM as the return Message.
 * If the implementation requires that the EM parameter be unmodified then the implementation should pass in a clone of the EM buffer.
 *
 * https://tools.ietf.org/html/rfc3447#section-7.1.2
 */
module.exports = function(buffer, label) {

  var hLen = 32;

  // Check to see if buffer is a properly encoded OAEP message
  if (buffer.length < 2 * hLen + 2) {
    throw new Error("Error decoding message, the supplied message is not long enough to be a valid OAEP encoded message");
  }

  var seed = buffer.slice(1, hLen + 1); // seed = maskedSeed
  var DB = buffer.slice(1 + hLen); // DB = maskedDB

  var mask = genmask_oaep_sha256(DB, hLen); // seedMask
  // XOR maskedSeed and seedMask together to get the original seed.
  for (var i = 0; i < seed.length; i++) {
    seed[i] ^= mask[i];
  }

  mask = genmask_oaep_sha256(seed, DB.length); // dbMask
  // XOR DB and dbMask together to get the original data block.
  for (i = 0; i < DB.length; i++) {
    DB[i] ^= mask[i];
  }

  var lHash = crypto.createHash('sha256');
  lHash.update(label);
  lHash = lHash.digest();

  var lHashEM = DB.slice(0, hLen);
  if (lHashEM.toString("hex") != lHash.toString("hex")) {
    throw new Error("Error decoding message, the lHash calculated from the label provided and the lHash in the encrypted data do not match.");
  }

  // Filter out padding
  i = hLen;
  while (DB[i++] === 0 && i < DB.length);
  if (DB[i - 1] != 1) {
    throw new Error("Error decoding message, there is no padding message separator byte");
  }

  return DB.slice(i); // Message
}