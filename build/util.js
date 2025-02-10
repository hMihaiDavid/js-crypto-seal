"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.utf8Decode = utf8Decode;
exports.utf8Encode = utf8Encode;
// XXX base64decode base64encode hexEncode hexDecode
function utf8Encode(str) {
  return new TextEncoder().encode(str);
}
function utf8Decode(data) {
  return new TextDecoder().decode(data);
}