'use strict';

var util = require('util');

var OAuth = require('./lib/oauth');
util._extend(OAuth.prototype, require('./lib/openapi'));

module.exports = OAuth;
