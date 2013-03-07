var assert = require('assert');
var achs = require('../index');

var tobuf = function(hexStr) {
  return new Buffer(hexStr, 'hex');
};


describe("getCiphers", function() {
  it('contains 3 elements', function(){
    assert.equal(3, achs.getCiphers().length);
  });
})

describe("getCipher", function() {
  var vectors = require('./vectors');

  Object.keys(vectors).forEach(function(alg) {
    describe(alg, function() {
      it('#check tag', function(done) {
        var testData = vectors[alg];
        var cipher = achs.createCipher(alg, tobuf(testData['K']), tobuf(testData['IV']), tobuf(testData['A']));

        cipher.on('tag', function(tag) {
          assert.equal(tag.toString('hex'), testData['T']);
          done();
        });

        cipher.write(tobuf(testData['P']));
        cipher.end();
      });


      it('#check encrypted content', function(done) {
        var testData = vectors[alg];
        var cipher = achs.createCipher(alg, tobuf(testData['K']), tobuf(testData['IV']), tobuf(testData['A']));

        var chunks = [];

        cipher.on('data', function(chunk) {
          chunks.push(chunk);
        });

        cipher.on('end', function() {
          assert.equal(Buffer.concat(chunks).toString('hex'), testData['E']);

          done();
        });

        cipher.write(tobuf(testData['P']));
        cipher.end();
      });

    });
  });

});
