# Authenticated Encryption with AES-CBC and HMAC-SHA2

For explanation see [the draft](http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-04).

Supported Algorithms:


|         algorithm        | key length  |
|--------------------------|-------------|
| aes-128-cbc-hmac-sha-256 |      32     |
| aes-192-cbc-hmac-sha-384 |      48     |
| aes-256-cbc-hmac-sha-512 |      56     |
| aes-256-cbc-hmac-sha-384 |      64     |



## Installation


    $ npm install --save aes-cbc-hmac-sha2


## Usage

Creating and using cipher/decipher is no different than [createCipheriv](http://nodejs.org/api/crypto.html#crypto_crypto_createcipheriv_algorithm_key_iv) and [createDecipheriv](http://nodejs.org/api/crypto.html#crypto_crypto_createdecipheriv_algorithm_key_iv) methods of node's [crypto module.](http://nodejs.org/api/crypto.html)

```js
var aesHmac = require('aes-cbc-hmac-sha2');

//cipher
var cipher = aesHmac.createCipheriv(algo, key, iv);

//decipher
var decipher = aesHmac.createDecipheriv(algo, key, iv);
```

Cipher and Decipher objects are streams that both readable and writable.

**You can also monkey-```patch``` node crypto module.**

```js
var crypto = require('crypto');
require('aes-cbc-hmac-sha2').patch(crypto);

var cipher = crypto.createCipheriv('aes-128-cbc-hmac-sha-256');
//...

```

### Encryption


```js
var aesHmac = require('aes-cbc-hmac-sha2');
var fs      = require('fs');

var key = new Buffer('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', 'base64'); //128-bit key
var iv  = new Buffer('GvOMLcK5b/3YZpQJI0G8BA==', 'base64'); // 128-bit initialization vector
var aad = new Buffer('VGhlIHNlY29uZCBwcmluY2lwbGUg', 'base64'); //additional authentication data
var plaintext  = fs.createReadStream('hello.txt');
var ciphertext = fs.createWriteStream('hello.txt.enc');

var cipher = aesHmac.createCipheriv('aes-128-cbc-hmac-sha-256', key, iv);
// additional authentication data must be set before encryption
cipher.setAAD(aad);

// we can get authentication tag once the writable side of the stream ended.
cipher.on('end', function() {
    console.log('Authentication Tag: ', cipher.getAuthTag().toString('base64')); //sYu58fmtWdfhYnenP6hzVA==
});

plaintext.pipe(cipher);
cipher.pipe(ciphertext);
```



### Decryption

Decryption operation have four inputs: ```key```, ```iv```, ```aad```, ```authTag``` and of course ```ciphertext```.

```js
var aesHmac = require('aes-cbc-hmac-sha2');
var fs      = require('fs');

var key = new Buffer('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', 'base64'); //128-bit key
var iv  = new Buffer('GvOMLcK5b/3YZpQJI0G8BA==', 'base64'); // 128-bit initialization vector
var aad = new Buffer('VGhlIHNlY29uZCBwcmluY2lwbGUg', 'base64'); // additional authentication data
var ciphertext = fs.createReadStream('hello.txt.enc');
var decryptedtext  = fs.createWriteStream('hello.txt.dec');

var decipher = aesHmac.createDecipheriv('aes-128-cbc-hmac-sha-256', key, iv);
decipher.setAAD(aad);

//
decipher.setAuthTag(new Buffer('sYu58fmtWdfhYnenP6hzVA==', 'base64'));

ciphertext.pipe(decipher);
decipher.pipe(decryptedtext);
```


## Running the tests
```sh
$ git clone https://github.com/glkz/aes-cbc-hmac-sha2.git
$ cd aes-cbc-hmac-sha2
$ npm install
$ npm test
```


## Further Reading

* [Authenticated Encryption with AES-CBC and HMAC-SHA](http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-04)
* [JSON Web Algorithms(JWA), AES_CBC_HMAC_SHA2 Algorithms](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#page-22)
