'use strict';

var crypto = require('crypto');
var querystring = require('querystring');
var httpx = require('httpx');
var streamx = require('streamx');
var uuid = require('node-uuid');

var sha1 = function (str, key) {
  return crypto.createHmac('sha1', key).update(str).digest("base64");
};

var OAuth = function (key, secret) {
  this.key = key;
  this.secret = secret;
  this.prefix = 'https://account.aliyun.com/';
};

OAuth.prototype.buildParams = function () {
  return {
    oauth_consumer_key: this.key,
    oauth_nonce: uuid.v4(),
    oauth_timestamp: OAuth.createTimestamp(),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_version: '1.0',
  };
};

OAuth.prototype.requestToken = function * (callbackUrl) {
  var url = this.prefix + 'oauth/request_token';
  var params = this.buildParams();
  params.oauth_callback = OAuth.encode(callbackUrl);

  var method = "GET";
  var normalized = OAuth.normalize(params);
  var signatured = this.signature(url, method, normalized);
  normalized.push(['oauth_signature', OAuth.encode(signatured)]);
  var opts = {
    method: method,
    headers: {'Authorization': OAuth.buildAuth(normalized)}
  };
  var response = yield httpx.request(url, opts);
  var buffer = yield streamx.read(response);
  var contentType = response.headers['content-type'] || '';
  if (contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
    return querystring.parse(buffer.toString());
  } else {
    var json = JSON.parse(buffer);
    if (json.errorCode) {
      throw new Error('OpenAPI: ' + json.errorMsg);
    }
    return json;
  }
};

OAuth.prototype.getAccessToken = function * (token, verifier, secret) {
  var url = this.prefix + 'oauth/access_token';
  var params = this.buildParams();
  params.oauth_token = token;
  params.oauth_verifier = verifier;

  var method = "GET";
  var normalized = OAuth.normalize(params);
  var signatured = this.signature(url, method, normalized, secret);
  normalized.push(['oauth_signature', OAuth.encode(signatured)]);
  var opts = {
    method: method,
    headers: {'Authorization': OAuth.buildAuth(normalized)}
  };
  var response = yield httpx.request(url, opts);
  var buffer = yield streamx.read(response);
  var contentType = response.headers['content-type'] || '';
  if (contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
    return querystring.parse(buffer.toString());
  } else {
    var json = JSON.parse(buffer);
    if (json.errorCode) {
      throw new Error('OpenAPI: ' + json.errorMsg);
    }
    return json;
  }
};

OAuth.prototype.getAuthUrl = function (token) {
  return this.prefix + 'oauth/authorize?oauth_token=' + token;
};

OAuth.buildAuth = function (normalized) {
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

OAuth.prototype.signature = function (url, method, normalized, secret) {
  var methodPart = method.toUpperCase();
  var urlPart = OAuth.encode(url);

  var parts = [];
  for (var i = 0; i < normalized.length; i++) {
    parts.push(normalized[i].join("="));
  }

  var params = OAuth.encode(parts.join("&"));
  var baseString = [methodPart, urlPart, params].join('&');
  var key = OAuth.encode(this.secret) + '&' + OAuth.encode(secret || '');

  return sha1(baseString, key);
};

OAuth.normalize = function (params) {
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
    item[0] = OAuth.encode(item[0]);
    item[1] = OAuth.encode(item[1]);
  }

  return list;
};

OAuth.createTimestamp = function () {
  return Math.floor((new Date()).getTime() / 1000);
};


OAuth.encode = function (str) {
  var result = encodeURIComponent(str);

  return result.replace(/\!/g, "%21")
   .replace(/\'/g, "%27")
   .replace(/\(/g, "%28")
   .replace(/\)/g, "%29")
   .replace(/\*/g, "%2A");
};

OAuth.prototype.load = function * (token, secret) {
  var url = this.prefix + 'openapi/id/load';
  var params = this.buildParams();
  params.oauth_token = token;
  var normalized = OAuth.normalize(params);

  var method = "GET";
  var signatured = this.signature(url, method, normalized, secret);
  normalized.push(['oauth_signature', OAuth.encode(signatured)]);
  var opts = {
    method: method,
    headers: {'Authorization': OAuth.buildAuth(normalized)}
  };
  var response = yield httpx.request(url, opts);
  var buffer = yield streamx.read(response);
  var contentType = response.headers['content-type'] || '';
  if (contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
    return querystring.parse(buffer.toString());
  } else {
    var json = JSON.parse(buffer);
    if (json.errorCode) {
      throw new Error('OpenAPI: ' + json.errorMsg);
    }
    return json;
  }
};

OAuth.prototype.aliyunid_kp = function * (token, secret) {
  var url = this.prefix + 'openapi/id/aliyunid_kp';
  var params = this.buildParams();
  params.oauth_token = token;
  var normalized = OAuth.normalize(params);

  var method = "GET";
  var signatured = this.signature(url, method, normalized, secret);
  normalized.push(['oauth_signature', OAuth.encode(signatured)]);
  var opts = {
    method: method,
    headers: {'Authorization': OAuth.buildAuth(normalized)}
  };

  var response = yield httpx.request(url, opts);
  var buffer = yield streamx.read(response);
  var contentType = response.headers['content-type'] || '';
  if (contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
    return querystring.parse(buffer.toString());
  } else {
    var json = JSON.parse(buffer);
    if (json.errorCode) {
      throw new Error('OpenAPI: ' + json.errorMsg);
    }
    return json;
  }
};

OAuth.prototype.timestamp = function * (secret) {
  var url = this.prefix + 'openapi/util/timestamp';
  var params = this.buildParams();
  var normalized = OAuth.normalize(params);

  var method = "GET";
  var signatured = this.signature(url, method, normalized, secret);
  normalized.push(['oauth_signature', OAuth.encode(signatured)]);
  var opts = {
    method: method,
    headers: {'Authorization': OAuth.buildAuth(normalized)}
  };

  var response = yield httpx.request(url, opts);
  var buffer = yield streamx.read(response);
  var contentType = response.headers['content-type'] || '';
  if (contentType.indexOf('application/x-www-form-urlencoded') !== -1) {
    return querystring.parse(buffer.toString());
  } else {
    var json = JSON.parse(buffer);
    if (json.errorCode) {
      throw new Error('OpenAPI: ' + json.errorMsg);
    }
    return json;
  }
};

module.exports = OAuth;
