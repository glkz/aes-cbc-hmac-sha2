'use strict';

var assert = require('assert');
var randBytes = require('crypto').pseudoRandomBytes;
var crypto = require('../index');

var algos = [
  ['aes-128-cbc-hmac-sha-256', 32],
  ['aes-192-cbc-hmac-sha-384', 48],
  ['aes-256-cbc-hmac-sha-512', 64],
  ['aes-256-cbc-hmac-sha-384', 56]
];

var MAX_PLAINTEXT_LENGTH = 2048;
var MAX_AAD_LENGTH = 512;
var ITERATIONS = 50;

algos.forEach(function(_algo) {
  var alg = _algo[0];
  var keySize = _algo[1];

  describe('Random Cipher/Decipher ' + alg, function() {
    for (var i = 0; i < ITERATIONS; i++) {
      it('#' + i, function() {
        var key = randBytes(keySize);
        var iv = randBytes(16);
        var aad = randBytes(Math.ceil(Math.random()) * MAX_AAD_LENGTH);
        var plaintext = randBytes(Math.ceil(Math.random()) * MAX_PLAINTEXT_LENGTH);

        var ciphertext;
        var authTag;

        var cipherChunks = [];
        var plainChunks = [];
        var plaintext2;

        var cipher = crypto.createCipheriv(alg, key, iv);

        cipher.setAAD(aad);
        cipherChunks.push(cipher.update(plaintext));
        cipherChunks.push(cipher.final());
        ciphertext = Buffer.concat(cipherChunks);
        authTag = cipher.getAuthTag();

        var decipher = crypto.createDecipheriv(alg, key, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(authTag);
        plainChunks.push(decipher.update(ciphertext));
        plainChunks.push(decipher.final());
        plaintext2 = Buffer.concat(plainChunks);

        /*
        console.log('key: ', key.toString('hex'));
        console.log('aad: ', aad.toString('hex'));
        console.log('iv: ', iv.toString('hex'));
        console.log('plaintext: ', plaintext.toString('hex'));
        console.log('ciphertext: ', ciphertext.toString('hex'));
        console.log('plaintext2: ', plaintext2.toString('hex'));
        */

        assert.equal(plaintext.toString('hex'), plaintext2.toString('hex'));
      });
    }
  });
});
