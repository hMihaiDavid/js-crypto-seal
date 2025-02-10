export class CryptoSealError extends Error {
    private __proto__: CryptoSealError;
    constructor(message?: string) {
        // https://stackoverflow.com/a/48342359/3537530
        // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html#support-for-newtarget
        super(message);

        const actualProto = new.target.prototype;
        if (Object.setPrototypeOf) { Object.setPrototypeOf(this, actualProto); }
        else { this.__proto__ = actualProto; }
    }
}

export class UNREACHABLE extends CryptoSealError { }