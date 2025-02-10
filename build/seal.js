"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.sealBuffer = sealBuffer;
exports.sealString = sealString;
exports.sealValue = sealValue;
exports.unsealBuffer = unsealBuffer;
exports.unsealString = unsealString;
exports.unsealValue = unsealValue;
var _uncrypto = require("uncrypto");
var _errors = require("./errors");
var _util = require("./util");
const assert = require('assert'); // XXX too heavy for our needs.

const DEFAULT_KDF_ROUNDS = 1000; // XXX

const DEFAULT_CIPHER_STRING = 'AES-256-CBC-HMAC-SHA-256';
const CIPHER_STRINGS_LIST = ['AES-256-GCM', 'AES-256-CBC-HMAC-SHA-256'];
function mapCipherAlias(cipher) {
  const aliases = {
    'AES': 'AES-256-CBC-HMAC-SHA-256',
    'AES-CBC': 'AES-256-CBC-HMAC-SHA-256',
    'AES-GCM': 'AES-256-GCM'
  };
  return aliases[cipher] || cipher;
}
async function sealValue(value, passphrase, opts) {
  return sealString(JSON.stringify(value), passphrase, opts);
}
async function sealString(data, passphrase, opts) {
  if (typeof data !== 'string') throw new _errors.CryptoSealError("Invalid 'data'");
  return sealBuffer((0, _util.utf8Encode)(data), passphrase, opts);
}
function isPlainObject(o) {
  return typeof o === 'object' && Object.getPrototypeOf(o) === Object.prototype;
}
async function sealBuffer(data, passphrase, opts) {
  if (!(data instanceof Uint8Array)) throw new _errors.CryptoSealError("Invalid 'data'.");
  if (typeof opts === 'undefined') opts = {};
  if (!isPlainObject(opts)) throw new _errors.CryptoSealError("'opts' must be a plain object.");
  opts.cipher = opts.cipher || DEFAULT_CIPHER_STRING;
  opts.cipher = mapCipherAlias(opts.cipher);
  if (!CIPHER_STRINGS_LIST.includes(opts.cipher)) throw new _errors.CryptoSealError("Invalid 'opts.cipher'.");
  switch (opts.cipher) {
    case 'AES-256-CBC-HMAC-SHA-256':
      return sealBufferAes256CbcHmacSha256(data, passphrase, opts);
    case 'AES-256-GCM':
      return sealBufferAes256Gcm(data, passphrase, opts);
  }
  throw new _errors.CryptoSealError("Unsupported/invalid cipher '".concat(opts.cipher, "'"));
}
async function unsealValue(data, passphrase, opts) {
  const jsonStr = await unsealString(data, passphrase, opts);
  return JSON.parse(jsonStr);
}
async function unsealString(data, passphrase, opts) {
  const decryptedData = await unsealBuffer(data, passphrase, opts);
  return (0, _util.utf8Decode)(new Uint8Array(decryptedData)); // XXX
}
async function unsealBuffer(data, passphrase, opts) {
  if (!(data instanceof Uint8Array)) throw new _errors.CryptoSealError("Invalid 'data'.");
  if (typeof opts === 'undefined') opts = {};
  if (!isPlainObject(opts)) throw new _errors.CryptoSealError("'opts' must be a plain object.");
  opts.cipher = opts.cipher || DEFAULT_CIPHER_STRING;
  opts.cipher = mapCipherAlias(opts.cipher);
  if (!CIPHER_STRINGS_LIST.includes(opts.cipher)) throw new _errors.CryptoSealError("Invalid 'opts.cipher'.");
  switch (opts.cipher) {
    case 'AES-256-CBC-HMAC-SHA-256':
      return unsealBufferAes256CbcHmacSha256(data, passphrase, opts);
    case 'AES-256-GCM':
      return unsealBufferAes256Gcm(data, passphrase, opts);
  }
  throw new _errors.CryptoSealError("Unsupported/invalid cipher '".concat(opts.cipher, "'"));
}
async function aes256CbcHmacSha256Derive(masterKey) {
  const cipherSalt = await hkdfDeriveBits(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/salt', 128);
  const cipherEncKey = await hkdfDeriveKeyObject(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/enckey', {
    name: 'AES-CBC',
    length: 256
  }, ['encrypt', 'decrypt']);
  const cipherAuthKey = await hkdfDeriveKeyObject(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/authkey', {
    name: 'HMAC',
    hash: 'SHA-256',
    length: 256
  }, ['sign', 'verify']);
  return {
    cipherSalt,
    cipherEncKey,
    cipherAuthKey
  };
}
async function sealBufferAes256CbcHmacSha256(data, passphrase, opts) {
  const salt = await randomSalt();
  const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds);
  const {
    cipherSalt,
    cipherEncKey,
    cipherAuthKey
  } = await aes256CbcHmacSha256Derive(masterKey);
  const encryptedBlob = new Uint8Array(await _uncrypto.subtle.encrypt({
    name: 'AES-CBC',
    iv: cipherSalt
  }, cipherEncKey, data));
  const result = new Uint8Array(16 /* salt */ + encryptedBlob.byteLength + 32 /* auth tag */);
  result.set(salt, 0);
  result.set(encryptedBlob, 16);
  const authTag = new Uint8Array(await _uncrypto.subtle.sign('HMAC', cipherAuthKey, result.subarray(0, 16 + encryptedBlob.byteLength)));
  assert(authTag.byteLength === 32);
  result.set(authTag, 16 + encryptedBlob.byteLength);
  return result;
}
async function unsealBufferAes256CbcHmacSha256(data, passphrase, opts) {
  if (data.byteLength < 16 + 32) throw new _errors.CryptoSealError("Invalid 'data'.");
  const salt = data.subarray(0, 16);
  const authData = data.subarray(0, data.byteLength - 32);
  const authTag = data.subarray(data.byteLength - 32);
  assert(authTag.length === 32);
  const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds);
  const {
    cipherSalt,
    cipherEncKey,
    cipherAuthKey
  } = await aes256CbcHmacSha256Derive(masterKey);
  const verifyRes = await _uncrypto.subtle.verify('HMAC', cipherAuthKey, authTag, authData);
  if (verifyRes !== true) throw new _errors.CryptoSealError("Authentication tag verification failed (tampered or corrupted message).");
  const encData = data.subarray(16, data.byteLength - 32); // XXX what happens if empty?
  return _uncrypto.subtle.decrypt({
    name: 'AES-CBC',
    iv: cipherSalt
  }, cipherEncKey, encData);
}
async function aes256GcmDerive(masterKey) {
  const cipherSalt = await hkdfDeriveBits(masterKey, '/v1/seal/AES-256-GCM/salt', 128);
  const cipherKey = await hkdfDeriveKeyObject(masterKey, '/v1/seal/AES-256-GCM/key', {
    name: 'AES-GCM',
    length: 256
  }, ['encrypt', 'decrypt']);
  return {
    cipherSalt,
    cipherKey
  };
}
async function sealBufferAes256Gcm(data, passphrase, opts) {
  const salt = await randomSalt();
  const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds);
  const {
    cipherSalt,
    cipherKey
  } = await aes256GcmDerive(masterKey);

  // XXX support additionalData
  const encryptedBlob = new Uint8Array(await _uncrypto.subtle.encrypt({
    name: 'AES-GCM',
    iv: cipherSalt,
    tagLength: 128
  }, cipherKey, data));
  const result = new Uint8Array(16 /* salt */ + encryptedBlob.byteLength);
  result.set(salt);
  result.set(encryptedBlob, 16);
  return result;
}
async function unsealBufferAes256Gcm(data, passphrase, opts) {
  if (data.byteLength < 16 + 16) throw new _errors.CryptoSealError("Invalid 'data'.");
  const salt = data.subarray(0, 16);
  const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds);
  const {
    cipherSalt,
    cipherKey
  } = await aes256GcmDerive(masterKey);
  const encData = data.subarray(16, data.byteLength);
  return _uncrypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: cipherSalt,
    tagLength: 128
  }, cipherKey, encData);
}
async function getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, rounds) {
  if (typeof passphrase === 'string') {
    passphrase = (0, _util.utf8Encode)(passphrase);
  }
  if (!(passphrase instanceof Uint8Array)) throw new _errors.CryptoSealError("Invalid 'passphrase'.");
  rounds = Math.floor(rounds || DEFAULT_KDF_ROUNDS);
  if (rounds in [Infinity, NaN] || rounds <= 0) throw new _errors.CryptoSealError("Invalid 'opts.rounds'.");
  return deriveHKDFKeyObjectFromPassphrase(passphrase, salt, rounds);
}
async function deriveHKDFKeyObjectFromPassphrase(value, salt, rounds) {
  const passphraseKeyObj = await _uncrypto.subtle.importKey('raw', value, 'PBKDF2', false, ['deriveKey']);
  const tmpKeyObject = await _uncrypto.subtle.deriveKey({
    name: 'PBKDF2',
    hash: 'SHA-256',
    // XXX think about this.
    salt,
    iterations: rounds
  }, passphraseKeyObj,
  // XXX workaround https://github.com/nodejs/node/issues/56931
  // {
  //     name: 'HMAC', // 'HKDF'
  //     hash: 'SHA-256', // XXX think about this.
  //     //info: (new TextEncoder()).encode('TODO'), // XXX
  //     //salt: new ArrayBuffer(32), // XXX
  //     //length: 32, // XXX
  // },
  {
    name: "AES-GCM",
    length: 256
  },
  // WORKAROUND
  true, ['encrypt', 'decrypt'] // not true
  );
  const tmpKey = await _uncrypto.subtle.exportKey('raw', tmpKeyObject);
  //console.log('tmpKEy:', tmpKey);
  assert(tmpKey.byteLength === 32);
  return _uncrypto.subtle.importKey('raw', tmpKey, {
    name: 'HKDF',
    hash: 'SHA-256'
    // length: 32, defaults to length of digest output.
    //length: 256,
  }, false, ['deriveKey', 'deriveBits']);
}
async function randomSalt() {
  const buffer = new Uint8Array(16); // XXX maybe digest it.
  await (0, _uncrypto.getRandomValues)(buffer);
  return buffer;
}
async function hkdfDeriveBits(hkdfKey, derivePath, nbits) {
  assert(derivePath.length > 0);
  return new Uint8Array(await _uncrypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    // XXX
    info: (0, _util.utf8Encode)(derivePath),
    salt: new ArrayBuffer(16)
  }, hkdfKey, nbits));
}
async function hkdfDeriveKeyObject(hkdfKey, derivePath, derivedKeyType, keyUsage) {
  assert(derivePath.length > 0);
  return _uncrypto.subtle.deriveKey({
    name: 'HKDF',
    hash: 'SHA-256',
    info: (0, _util.utf8Encode)(derivePath),
    salt: new ArrayBuffer(16) // 16 zeroes, because the hkdfKey should already be salty enough.
  }, hkdfKey, derivedKeyType, true, keyUsage); // XXX set extractable to false after debugging.
}