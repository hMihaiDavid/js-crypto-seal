"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UNREACHABLE = exports.CryptoSealError = void 0;
class CryptoSealError extends Error {
  constructor(message) {
    // https://stackoverflow.com/a/48342359/3537530
    // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html#support-for-newtarget
    super(message);
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
  }
}
exports.CryptoSealError = CryptoSealError;
class UNREACHABLE extends CryptoSealError {}
exports.UNREACHABLE = UNREACHABLE;