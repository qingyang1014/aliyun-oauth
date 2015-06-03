'use strict';

var crypto = require('crypto');

exports.sha1 = function (str, key) {
  return crypto.createHmac('sha1', key).update(str).digest("base64");
};

exports.createTimestamp = function () {
  return Math.floor((new Date()).getTime() / 1000);
};

exports.normalize = function (params) {
  var list = [];
  var keys = Object.keys(params).sort();
  for (let i = 0; i < keys.length; i++) {
    var key = keys[i];
    list.push([key, params[key]]);
  }

  list.sort(function(a, b) {
    if (a[0] < b[0]) {
      return -1;
    }
    if (a[0] > b[0]) {
      return 1;
    }
    // key相同，比较value
    if (a[1] < b[1]) {
      return -1;
    }
    if (a[1] > b[1]) {
      return 1;
    }

    return 0;
  });

  for (let i = 0; i < list.length; i++) {
    var item = list[i];
    item[0] = exports.encode(item[0]);
    item[1] = exports.encode(item[1]);
  }

  return list;
};

exports.encode = function (str) {
  var result = encodeURIComponent(str);

  return result.replace(/\!/g, "%21")
   .replace(/\'/g, "%27")
   .replace(/\(/g, "%28")
   .replace(/\)/g, "%29")
   .replace(/\*/g, "%2A");
};

exports.buildAuth = function (normalized) {
  var fields = [];
  for (var i = 0; i < normalized.length; i++) {
    var param = normalized[i];
    var key = param[0];
    var value = param[1];
    if (key.indexOf('oauth_') !== -1) {
      fields.push(key + '="' + value + '"');
    }
  }
  return 'OAuth ' + fields.join(', ');
};
