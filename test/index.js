"use strict";

var should = require('chai').should();
var kaspacore = require('../');

describe('#versionGuard', function() {
  it('global._kaspacoreLibVersion should be defined', function() {
    should.equal(global._kaspacoreLibVersion, kaspacore.version);
  });

  it('throw an error if version is already defined', function() {
    (function() {
      kaspacore.versionGuard('version');
    }).should.throw('More than one instance of bitcore');
  });
});
