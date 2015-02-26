'use strict';

var assert = require('assert');

var tobuf = function(hexStr) {
  return new Buffer(hexStr, 'hex');
};

var vectors = (function() {
  var hexFields = ['K', 'MAC_KEY', 'ENC_KEY', 'P', 'IV', 'A', 'AL', 'E', 'M', 'T'];

  return require('./data/vectors').map(function(vec) {
    var ret = {};
    Object.keys(vec).forEach(function(prop) {
      ret[prop] = (hexFields.indexOf(prop) !== -1) ? tobuf(vec[prop]) : vec[prop];
    });

    return ret;
  });
})();

var cipherWriteSync = function(cipher, data) {
  var chunks = [];
  chunks.push(cipher.update(data));
  chunks.push(cipher.final());

  return Buffer.concat(chunks);
};

var cipherWriteAsync = function(cipher, data, end) {
  var chunks = [];

  cipher.on('data', function(chunk) {
    chunks.push(chunk);
  });

  cipher.on('end', function() {
    end(Buffer.concat(chunks));
  });

  cipher.write(data);
  cipher.end();
};

var initTests = function(crypto) {
  describe('getCiphers', function() {
    [
      'aes-128-cbc-hmac-sha-256',
      'aes-192-cbc-hmac-sha-384',
      'aes-256-cbc-hmac-sha-512',
      'aes-256-cbc-hmac-sha-384'
    ].forEach(function(algo) {
      it('should support ' + algo, function() {
        assert.notEqual(crypto.getCiphers().indexOf(algo), -1);
      });
    });

  });

  describe('Cipher Sync', function() {
    vectors.forEach(function(vec) {
      describe(vec.ALG, function() {
        var cipher = crypto.createCipheriv(vec.ALG, vec.K, vec.IV);
        cipher.setAAD(vec.A);
        var ciphertext = cipherWriteSync(cipher, vec.P);

        it('#check tag', function() {
          assert.equal(cipher.getAuthTag().toString('hex'), vec.T.toString('hex'));
        });

        it('#check ciphertext', function() {
          assert.equal(ciphertext.toString('hex'), vec.E.toString('hex'));
        });

      });
    });
  });

  describe('Decipher Sync', function() {
    vectors.forEach(function(vec) {
      describe(vec.ALG, function() {

        var decipher = crypto.createDecipheriv(vec.ALG, vec.K, vec.IV);
        decipher.setAAD(vec.A);
        decipher.setAuthTag(vec.T);
        var plaintext = cipherWriteSync(decipher, vec.E);

        it('#check tag', function() {
          assert.equal(decipher.getAuthTag().toString('hex'), vec.T.toString('hex'));
        });

        it('#check ciphertext', function() {
          assert.equal(plaintext.toString('hex'), vec.P.toString('hex'));
        });

      });
    });
  });

  describe('Cipher Stream', function() {
    vectors.forEach(function(vec) {
      describe(vec.ALG, function() {

        it('#check tag&ciphertext', function(done) {
          var cipher = crypto.createCipheriv(vec.ALG, vec.K, vec.IV);
          cipher.setAAD(vec.A);
          cipherWriteAsync(cipher, vec.P, function(ciphertext) {
            assert.equal(ciphertext.toString('hex'), vec.E.toString('hex'));
            assert.equal(cipher.getAuthTag().toString('hex'), vec.T.toString('hex'));

            done();
          });
        });

      });
    });
  });

  describe('Decipher Stream', function() {
    vectors.forEach(function(vec) {
      describe(vec.ALG, function() {

        it('#check tag&ciphertext', function(done) {
          var decipher = crypto.createDecipheriv(vec.ALG, vec.K, vec.IV);
          decipher.setAAD(vec.A);
          decipher.setAuthTag(vec.T);

          cipherWriteAsync(decipher, vec.E, function(plaintext) {
            assert.equal(plaintext.toString('hex'), vec.P.toString('hex'));
            assert.equal(decipher.getAuthTag().toString('hex'), vec.T.toString('hex'));
            done();
          });

        });

      });
    });
  });

  describe('Cipher State Exceptions', function() {
    var vec    = vectors[0];
    var algo   = vec.ALG;
    var key    = vec.K;
    var iv     = vec.IV;

    it('#setAAD must be before encryption', function(done) {
      var cipher = crypto.createCipheriv(algo, key, iv);
      cipher.update(new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]));

      assert.throws(function() {
        cipher.setAAD(new Buffer([9, 8, 7, 6, 5, 4, 3, 2, 1]));
      }, function() {
        done();
        return true;
      });
    });

    it('#getAuthTag must be after encryption', function(done) {
      var cipher = crypto.createCipheriv(algo, key, iv);
      cipher.update(new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]));

      assert.throws(cipher.getAuthTag, function() {
        done();
        return true;
      });
    });
  });

  describe('Decipher State Exceptions', function() {
    var vec    = vectors[0];
    var algo   = vec.ALG;
    var key    = vec.K;
    var iv     = vec.IV;

    it('#must call setAuthTag before write', function(done) {
      var decipher = crypto.createDecipheriv(algo, key, iv);

      assert.throws(function() {
        decipher.update(new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]));
      }, function() {
        done();
        return true;
      });
    });

    it('#getAuthTag must be after encryption', function(done) {
      var decipher = crypto.createDecipheriv(algo, key, iv);
      decipher.setAuthTag(vec.T);
      decipher.update(vec.E);

      assert.throws(function() {
        decipher.final();
      }, function(err) {
        done();
        return /failed/.test(err);
      });
    });
  });
};

describe('direct', function() {
  initTests(require('../index'));
});

describe('patched', function() {
  initTests(require('../index').patch(require('crypto')));
});
