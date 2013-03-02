var crypto = require('crypto');
var util = require('util');
var Transform = require('stream').Transform;

var AES_CBC_HMAC_SHA2_Transform = function(filter, hmac, AL, T_LEN, options) {
  Transform.call(this, options);

  this.filter = filter;
  this.hmac = hmac;
  this.AL = AL;
  this.T_LEN = T_LEN;
};
util.inherits(AES_CBC_HMAC_SHA2_Transform, Transform);



AES_CBC_HMAC_SHA2_Transform.prototype._transform = function(chunk, enc, cb) {
  var filteredChunk = this.filter.update(chunk, enc);
  this.hmac.write(filteredChunk);

  this.push(filteredChunk);
  cb();
};

AES_CBC_HMAC_SHA2_Transform.prototype._flush = function(cb) {
  var remaining = this.filter.final();

  if (remaining.length) {
    this.push(remaining);
    this.hmac.write(remaining);
  }

  this.hmac.write(this.AL);

  var tag = this.hmac.digest().slice(0, this.T_LEN);

  this.emit('tag', tag);
  cb();
};

var parseKey = function(key, ENC_KEY_LEN, MAC_KEY_LEN) {
  var KEY_LEN = ENC_KEY_LEN + MAC_KEY_LEN;

  if (key.length !== KEY_LEN) {
    throw new Error('Key must be ' + KEY_LEN + ' octets long.');
  }

  return {
    MAC_KEY: key.slice(0, MAC_KEY_LEN),
    ENC_KEY: key.slice(MAC_KEY_LEN)
  };
};

var getAL = function(aad) {
  var AL = new Buffer(8);

  //@fix assumed A.length * 8 will fit 32bit
  AL.writeUInt32BE(aad.length * 8, 4);
  AL.writeUInt32BE(0, 0);

  return AL;
};

var createGenericCipher = function(ENC_KEY_LEN, MAC_KEY_LEN, T_LEN, hashAlgo, cipherAlgo) {
  return function(key, iv, aad) {
    // todo check key type (Buffer)
    if (!(key instanceof Buffer) || !(aad instanceof Buffer) || !(iv instanceof Buffer)) {
      throw new Error('key, aad and iv must be instances of Buffer');
    }

    if (iv.length !== 16) {
      throw new Error('Initialization vector must be 128 bit.');
    }

    var KEYS = parseKey(key, ENC_KEY_LEN, MAC_KEY_LEN);
    var AL = getAL(aad);

    var cipher = crypto.createCipheriv(cipherAlgo, KEYS.ENC_KEY, iv);
    var hmac = crypto.createHmac(hashAlgo, KEYS.MAC_KEY);

    cipher.setAutoPadding(true);

    hmac.write(aad);
    hmac.write(iv);

    //return new AES_CBC_HMAC_SHA2_Transform(cipher, hmac, AL, T_LEN);

    
    cipher.on('data', function(chunk) {
      hmac.write(chunk);
    });

    cipher.on('end', function() {
      hmac.write(AL);
      var tag = hmac.digest().slice(0, T_LEN);

      cipher.emit('tag', tag);

    });

    return cipher;
  };
};

var createGenericDecipher = function() {

};


var algos = {
  'AES_128_CBC_HMAC_SHA_256': [16, 16, 16, 'sha256', 'aes-128-cbc'],
  'AES_192_CBC_HMAC_SHA_384': [24, 24, 24, 'sha384', 'aes-192-cbc'],
  'AES_256_CBC_HMAC_SHA_512': [32, 32, 32, 'sha512', 'aes-256-cbc']
};

module.exports.createGenericCipher = createGenericCipher;
module.exports.createCipher = function(algo, key, iv, aad) {
  if (algos[algo] === undefined) {
    throw new Error(algo + ' is not supported.');
  }

  return createGenericCipher.apply(this, algos[algo]).call(null, key, iv, aad);
};

module.exports.getCiphers = function() {
  return Object.keys(algos);
}
