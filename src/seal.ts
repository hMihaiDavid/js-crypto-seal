//import { TextEncoder, TextDecoder } from 'util';
// XXX TODO TextEncoder in the browser is somewhere else, see how uncrypto does conditional imports.

// TODO:
// gen typigs into separate folder,
// make separate branch that cntain the babel and the dist for npm install and unpkg/jsdelivr.
// put gen files in gitignore here
// generate webpack mappings
// make sure typings are accesible after an npm install of this library.
// remove uncrypto dep and see if the util textencoder is ok to assume it's global.

import { subtle, getRandomValues } from 'uncrypto';

// XXX
function assert(cond: any, s?: string) {
    if (!cond) {
        throw new Error(s || "");
    }
}

// XXX base64decode base64encode hexEncode hexDecode
function utf8Encode(str: string): Uint8Array {
    return (new TextEncoder()).encode(str);
}

function utf8Decode(data: Uint8Array): string {
    return (new TextDecoder()).decode(data);
}


const DEFAULT_KDF_ROUNDS = 10; // XXX

const DEFAULT_CIPHER_STRING = 'AES-256-CBC-HMAC-SHA-256';
const CIPHER_STRINGS_LIST = ['AES-256-CBC-HMAC-SHA-256'];

type StringToString = { [key: string]: string; };

function mapCipherAlias(cipher: string): string {
    const aliases: StringToString = {
        'AES':     'AES-256-CBC-HMAC-SHA-256',
        'AES-CBC': 'AES-256-CBC-HMAC-SHA-256',
        'AES-GCM': 'AES-256-GCM',
    };

    return aliases[cipher] || cipher; 
}

// XXX advanced sealopts values: deconstruct {outputSalt, outputAuthTag...}, maybe, maybe not.
export interface SealOptions {
    kdfRounds?: number; // TODO if this is 0, disable kdf and use raw key material, but only if provided as buffer, or allow rawKey
    cipher?: string; // TODO for later.
    rawKey?: Uint8Array,
}

async function debugDumpKeyObj(s: string, key: any) {
    console.log(s, await subtle.exportKey('raw', key));
}

export async function sealValue(value: any, passphrase: string | Uint8Array, opts?: SealOptions) {
    return sealString(JSON.stringify(value), passphrase, opts);
}

export async function sealString(data: string, passphrase: string | Uint8Array, opts?: SealOptions) {
    if (typeof(data) !== 'string') throw new Error("Invalid 'data'");
    return sealBuffer(utf8Encode(data), passphrase, opts);
}

function isPlainObject(o: Object) {
    return typeof(o) === 'object' && Object.getPrototypeOf(o) === Object.prototype;
}

// XXX consider using BufferSource as parameters like the web api
// XXX dealloc keys as soon as they're not neeeded. and memset them to 0 first!
export async function sealBuffer(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions) {
    if (!(data instanceof Uint8Array)) throw new Error("Invalid 'data'.");
    if (typeof(opts) === 'undefined') opts = {};
    if (!isPlainObject(opts)) throw new Error("'opts' must be a plain object.");

    opts.cipher = opts.cipher || DEFAULT_CIPHER_STRING;
    if (!CIPHER_STRINGS_LIST.includes(opts.cipher)) throw new Error("Invalid 'opts.cipher'.");

    const salt = await randomSalt();
    const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds, opts.rawKey);
    
    opts.cipher = mapCipherAlias(opts.cipher);

    switch (opts.cipher) {
        case 'AES-256-CBC-HMAC-SHA-256':
            return sealBufferAes256CbcHmacSha256(data, masterKey, salt);
    }

    throw new Error('UNREACHABLE');
}

export async function unsealValue(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions) {
    const jsonStr = await unsealString(data, passphrase, opts);
    return JSON.parse(jsonStr);
}

export async function unsealString(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions): Promise<string> {
    const decryptedData = await unsealBuffer(data, passphrase, opts);
    return utf8Decode(new Uint8Array(decryptedData)); // XXX
}

export async function unsealBuffer(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions) {
    if (!(data instanceof Uint8Array)) throw new Error("Invalid 'data'.");
    if (typeof(opts) === 'undefined') opts = {};
    if (!isPlainObject(opts)) throw new Error("'opts' must be a plain object.");

    opts.cipher = opts.cipher || DEFAULT_CIPHER_STRING;
    if (!CIPHER_STRINGS_LIST.includes(opts.cipher)) throw new Error("Invalid 'opts.cipher'.");

    opts.cipher = mapCipherAlias(opts.cipher);

    switch (opts.cipher) {
        case 'AES-256-CBC-HMAC-SHA-256':
            return unsealBufferAes256CbcHmacSha256(data, passphrase, opts);
    }

    throw new Error('UNREACHABLE');
}

async function aes256CbcHmacSha256Derive(masterKey: CryptoKey) {
    const cipherSalt = await hkdfDeriveBits(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/salt', 128);

    const cipherEncKey = await hkdfDeriveKeyObject(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/enckey',
        { name: 'AES-CBC', length: 256 }, ['encrypt', 'decrypt']);
    const cipherAuthKey = await hkdfDeriveKeyObject(masterKey, '/v1/seal/AES-256-CBC-HMAC-SHA-256/authkey',
        { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign', 'verify']);
    
    return { cipherSalt, cipherEncKey, cipherAuthKey };
}

async function sealBufferAes256CbcHmacSha256(data: Uint8Array, masterKey: CryptoKey, salt: Uint8Array) {
    const { cipherSalt, cipherEncKey, cipherAuthKey } = await aes256CbcHmacSha256Derive(masterKey);

    //await debugDumpKeyObj('seal auth key:', cipherAuthKey);

    const encryptedBlob = new Uint8Array(await subtle.encrypt({
        name: 'AES-CBC',
        iv: cipherSalt,
    }, cipherEncKey, data));

    const result = new Uint8Array(16 /* salt */ + encryptedBlob.byteLength + 32 /* auth tag */);
    result.set(salt, 0);
    result.set(encryptedBlob, 16);
    
    const authTag = new Uint8Array(await subtle.sign('HMAC', cipherAuthKey, result.subarray(0, 16 + encryptedBlob.byteLength)));
    assert(authTag.byteLength === 32);
    result.set(authTag, 16 + encryptedBlob.byteLength);

    return result;
}

async function unsealBufferAes256CbcHmacSha256(data: Uint8Array, passphrase: string | Uint8Array, opts: SealOptions) {
    if (data.byteLength < 16 + 32) throw new Error("Invalid 'data'.");
    const salt = data.subarray(0, 16);
    const authData = data.subarray(0, data.byteLength - 32);
    const authTag = data.subarray(data.byteLength - 32);
    assert(authTag.length === 32);
    //console.log('unseal auth tag:', authTag);

    const masterKey = await getHKDFKeyObjectFromPassphraseOrKey(salt, passphrase, opts.kdfRounds, opts.rawKey);
    const { cipherSalt, cipherEncKey, cipherAuthKey } = await aes256CbcHmacSha256Derive(masterKey);
    

    //await debugDumpKeyObj('unseal auth key:', cipherAuthKey);

    const verifyRes = await subtle.verify('HMAC', cipherAuthKey, authTag, authData);
    //console.log('////// verifyRes', verifyRes);
    if (verifyRes !== true) throw new Error("Invalid 'data' (authentication tag verification failed).");

    const encData = data.subarray(16, data.byteLength - 32); // XXX what happens if empty?
    return subtle.decrypt({
        name: 'AES-CBC',
        iv: cipherSalt,
    }, cipherEncKey, encData);
}

async function getHKDFKeyObjectFromPassphraseOrKey(
    salt: Uint8Array, passphrase?: string | Uint8Array, rounds?: number, rawKey?: Uint8Array
): Promise<CryptoKey> {
    if (passphrase) {
        if (typeof(rawKey) !== 'undefined')
            throw new Error("You can either provide a 'passphrase' or an 'opts.rawKey', not both.");

        if (typeof(passphrase) === 'string') {
            passphrase = utf8Encode(passphrase);
        }
        if (!(passphrase instanceof Uint8Array))
            throw new Error("Invalid 'passphrase'.");
        
        rounds = Math.floor(rounds || DEFAULT_KDF_ROUNDS);
        if (rounds in [Infinity, NaN] || rounds <= 0) throw new Error("Invalid 'rounds'.");

        return deriveHKDFKeyObjectFromPassphrase(passphrase, salt, rounds);
    } else if (rawKey) {
        if (typeof(passphrase) !== 'undefined')
            throw new Error("You can either provide a 'passphrase' or an 'opts.rawKey', not both.");
        
        if (!(rawKey instanceof Uint8Array))
            throw new Error("Invalid 'opts.rawKey'.");

        assert(false, "UNIMPLEMENTED");
    }
    
    throw new Error("Either 'passphrase' or 'opts.rawKey' must be provided.");
}

async function deriveHKDFKeyObjectFromPassphrase(value: Uint8Array, salt: Uint8Array, rounds: number): Promise<CryptoKey> {
    const passphraseKeyObj = await subtle.importKey('raw', value, 'PBKDF2', false, ['deriveKey']);

    const tmpKeyObject = await subtle.deriveKey({
        name: 'PBKDF2',
        hash: 'SHA-256', // XXX think about this.
        salt,
        iterations: rounds,
    }, passphraseKeyObj,
    // XXX workaround https://github.com/nodejs/node/issues/56931
    // {
    //     name: 'HMAC', // 'HKDF'
    //     hash: 'SHA-256', // XXX think about this.
    //     //info: (new TextEncoder()).encode('TODO'), // XXX
    //     //salt: new ArrayBuffer(32), // XXX
    //     //length: 32, // XXX
    // },
    { name: "AES-GCM", length: 256 }, // WORKAROUND
    true, ['encrypt', 'decrypt'] // not true
    );

    const tmpKey = await subtle.exportKey('raw', tmpKeyObject);
    //console.log('tmpKEy:', tmpKey);
    assert(tmpKey.byteLength === 32);
    
    return subtle.importKey('raw', tmpKey, {
        name: 'HKDF',
        hash: 'SHA-256',
        // length: 32, defaults to length of digest output.
        //length: 256,
    }, false, ['deriveKey', 'deriveBits']);
}

async function randomSalt() {
    const buffer = new Uint8Array(16); // XXX maybe digest it.
    await getRandomValues(buffer);
    return buffer;

}

// XXX return value type, in all funcs
async function hkdfDeriveBits(hkdfKey: CryptoKey, derivePath: string, nbits?: number) {
    assert(derivePath.length > 0);
    return new Uint8Array(await subtle.deriveBits({
        name: 'HKDF',
        hash: 'SHA-256', // XXX
        info: utf8Encode(derivePath),
        salt: new ArrayBuffer(16),
    }, hkdfKey, nbits));
}

async function hkdfDeriveKeyObject(hkdfKey: CryptoKey, derivePath: string, derivedKeyType: any, keyUsage: KeyUsage[]): Promise<CryptoKey> {
    assert(derivePath.length > 0);
    return subtle.deriveKey({
        name: 'HKDF',
        hash: 'SHA-256',
        info: utf8Encode(derivePath),
        salt: new ArrayBuffer(16), // 16 zeroes, because the hkdfKey should already be salty enough.
    }, hkdfKey, derivedKeyType, true, keyUsage); // XXX set extractable to false after debugging.
}