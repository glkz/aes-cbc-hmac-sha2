'use strict';

var crypto = require('crypto');

var splitKey = function(key, i) {
  return {
    MAC_KEY: key.slice(0, i),
    ENC_KEY: key.slice(i)
  };
};

var uint64Buffer = function(num) {
  var AL = new Buffer(8);
  AL.writeUInt32BE(num, 4);
  AL.writeUInt32BE(0, 0);

  return AL;
};

var init = function(key, iv, cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN, type) {
  if (!(key instanceof Buffer) || !(iv instanceof Buffer)) {
    throw new Error('key and iv must be instances of Buffer');
  }

  if (iv.length !== 16) {
    throw new Error('IV must be 16 octets long.');
  }

  if (key.length !== ENC_KEY_LEN + MAC_KEY_LEN) {
    throw new Error('Key must be ' + (ENC_KEY_LEN + MAC_KEY_LEN) + ' octets long.');
  }

  var keys = splitKey(key, MAC_KEY_LEN);

  var cipher = crypto['create' + type + 'iv'](cipherAlgo, keys.ENC_KEY, iv);
  cipher._hmac = crypto.createHmac(hashAlgo, keys.MAC_KEY);
  cipher._tagLength = T_LEN;
  cipher._aadLength = uint64Buffer(0);
  cipher._cipherStarted = false;
  cipher._cipherFinalized = false;

  cipher.setAAD = function(aad) {
    if (!(aad instanceof Buffer)) {
      throw new TypeError('AAD must be a Buffer');
    }

    if (cipher._cipherStarted) {
      throw new Error('Attempting to set AAD in unsupported state');
    }

    cipher._hmac.write(aad);
    cipher._hmac.write(iv);

    cipher._aadLength = uint64Buffer(aad.length * 8);
  };

  cipher.getAuthTag = function() {
    if (!cipher._cipherFinalized) {
      throw new Error('Attempting to get auth tag in unsupported state');
    }

    return cipher._authTag;
  };

  cipher.setAuthTag = function(_expectedAuthTag) {
    cipher._expectedAuthTag = _expectedAuthTag;
  };

  cipher._transform = function(chunk, encoding, callback) {
    this.push(this.update(chunk, encoding));
    callback();
  };

  cipher._flush = function(callback) {
    try {
      this.push(this.final());
    } catch (e) {
      callback(e);
      return;
    }
    callback();
  };

  return cipher;
};

var initCipher = function(key, iv, cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN) {
  var cipher = init(key, iv, cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN, 'Cipher');

  var _update = cipher.update;
  var _final = cipher.final;

  cipher.update = function(data, inputEncoding, outputEncoding) {
    cipher._cipherStarted = true;

    var ret = _update.call(cipher, data, inputEncoding, outputEncoding);

    cipher._hmac.update(ret);
    return ret;
  };

  cipher.final = function(outputEncoding) {
    var ret = _final.call(cipher, outputEncoding);

    cipher._hmac.update(ret);

    cipher._hmac.update(cipher._aadLength);
    cipher._authTag = cipher._hmac.digest().slice(0, cipher._tagLength);
    cipher._cipherFinalized = true;

    return ret;
  };

  return cipher;
};

///////

var initDecipher = function(key, iv, cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN) {
  var decipher = init(key, iv, cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN, 'Decipher');

  var _update = decipher.update;
  var _final = decipher.final;

  decipher.update = function(data, inputEncoding, outputEncoding) {
    if (!decipher._expectedAuthTag) {
      throw new Error('No authTag provided. Use decipher#setAuthTag method first.');
    }

    decipher._cipherStarted = true;
    decipher._hmac.update(data);

    return _update.call(decipher, data, inputEncoding, outputEncoding);
  };

  decipher.final = function(outputEncoding) {
    var ret = _final.call(decipher, outputEncoding);

    decipher._hmac.update(decipher._aadLength);
    decipher._authTag = decipher._hmac.digest().slice(0, decipher._tagLength);
    decipher._cipherFinalized = true;

    if (!decipher._expectedAuthTag || decipher._authTag.toString('hex') !== decipher._expectedAuthTag.toString('hex')) {
      throw new Error('Authentication failed.');
    }

    return ret;
  };

  return decipher;
};

// algo -> [cipherAlgo, hashAlgo, MAC_KEY_LEN, ENC_KEY_LEN, T_LEN]
var algos = {
  'aes-128-cbc-hmac-sha-256': ['aes-128-cbc', 'sha256', 16, 16, 16],
  'aes-192-cbc-hmac-sha-384': ['aes-192-cbc', 'sha384', 24, 24, 24],
  'aes-256-cbc-hmac-sha-512': ['aes-256-cbc', 'sha512', 32, 32, 32],
  'aes-256-cbc-hmac-sha-384': ['aes-256-cbc', 'sha384', 24, 32, 24]
};

var createCipheriv = module.exports.createCipheriv = function(algo, key, iv) {
  if (algos[algo] === undefined) {
    throw new Error('Unknown cipher ' + algo);
  }

  var params = algos[algo].slice(0);
  return initCipher(key, iv, params[0], params[1], params[2], params[3], params[4]);
};

var createDecipheriv = module.exports.createDecipheriv = function(algo, key, iv) {
  if (algos[algo] === undefined) {
    throw new Error('Unknown cipher ' + algo);
  }

  var params = algos[algo].slice(0);
  return initDecipher(key, iv, params[0], params[1], params[2], params[3], params[4]);
};

var getCiphers = module.exports.getCiphers = function() {
  return Object.keys(algos);
};

module.exports.patch = function(nodeCrypto) {
  var _getCiphers = nodeCrypto.getCiphers;
  var _createCipheriv = nodeCrypto.createCipheriv;
  var _createDecipheriv = nodeCrypto.createDecipheriv;

  nodeCrypto.getCiphers = function() {
    return _getCiphers().concat(getCiphers());
  };

  nodeCrypto.createCipheriv = function(algorithm, key, iv) {
    if (algos[algorithm]) {
      return createCipheriv(algorithm, key, iv);
    }

    return _createCipheriv(algorithm, key, iv);
  };

  nodeCrypto.createDecipheriv = function(algorithm, key, iv) {
    if (algos[algorithm]) {
      return createDecipheriv(algorithm, key, iv);
    }

    return _createDecipheriv(algorithm, key, iv);
  };

  return nodeCrypto;
};
