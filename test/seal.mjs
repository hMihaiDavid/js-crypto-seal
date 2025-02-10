import assert from "assert";
import _ from 'lodash';
import { describe } from "mocha"; // XXX

import { sealString, unsealString, sealBuffer, unsealBuffer } from "../build/index.js"; // XXX without index.js doesn't work, LOOKINTO
import { AssertionError } from "assert";

// XXX put in separate test utils file...
// XXX make more idiomatic and produce more readable assertions.
function assertNotEqualBuffers(buf1, buf2) {
    assert(_.isTypedArray(buf1) && _.isTypedArray(buf2));
    if (buf1.byteLength !== buf2.byteLength) { return; }

    for (let i = 0; i < buf1.byteLength; ++i) {
        if (buf1[i] !== buf2[i]) { return; }
    }

    throw new AssertionError("Buffers are equal.")
}

describe("seal API", () => {
    [undefined /* default */, 'AES', 'AES-CBC', 'AES-GCM', 'AES-256-CBC-HMAC-SHA-256', 'AES-256-GCM'].forEach((cipherStr) => {
        const opts = cipherStr ? { cipher: cipherStr } : undefined;

        describe(`Basic positive tests with cipher ${cipherStr ? cipherStr : "DEFAULT"}`, () => {
            it("should round-trip a message with an empty password", async () => {
                const ct = await sealString('hello world!', '', opts);
                const dt = await unsealString(ct, '', opts);
                assert.strictEqual(dt, 'hello world!');
            })
            it("should round-trip a message with an empty buffer password", async () => {
                const ct = await sealString('hello world!', new Uint8Array(), opts);
                const dt = await unsealString(ct, new Uint8Array(), opts);
                assert.strictEqual(dt, 'hello world!');
            })
            it("should round-trip an empty message", async () => {
                const ct = await sealString('', 'password', opts);
                const dt = await unsealString(ct, 'password', opts);
                assert.strictEqual(dt, '');
            })
            it("should round-trip an empty buffer message", async () => {
                const ct = await sealBuffer(new Uint8Array(), 'password', opts);
                const dt = await unsealBuffer(ct, 'password', opts);
                assert.equal(dt.byteLength, 0);
                assert.ok(ct.byteLength >= 32);
            })
            _.forEach([10, 100, 100000000], (msgLen) => {
                it(`should round-trip a ${msgLen} bytes message`, async () => {
                    const msg = 'A'.repeat(msgLen);
                    const ct = await sealString(msg, 'some_Password_1234!', opts);
                    const dt = await unsealString(msg, 'some_Password_1234!', opts);
                    assert.equal(dt, msg);
                })
            })
        })
    })

    _.forEach(_.zip(
        ['AES-256-CBC-HMAC-SHA-256', 'AES-256-GCM'], [[0, 0.3], [3000, 0.1]]), ([ cipher, [ msgLen, epsillon ] ]) => {
        it(`${cipher} should produce different ciphertexts for the same message encrypted with same password (msglen ${msgLen}) [hamming + strict]`, async () => {
            const hammingDistance = (num1, num2) => ((num1 ^ num2).toString(2).match(/1/g) || '').length;

            const cts = [];
            for (let i = 0; i < 20; ++i) {
                assert(msgLen >= 0);
                cts.push(await sealString('A'.repeat(msgLen), '', { cipher })); // Note: 'A'.repeat(0) produces '', which will be an empty message.
                // XXX use 0xff instead of A
            }
            
            let distAcc = 0;
            let numBytes = 0;
            cts.forEach((ctA) => {
                cts.forEach((ctB) => {
                    if (ctA === ctB) { return; }

                    assertNotEqualBuffers(ctA.subarray(0, 16), ctB.subarray(0, 16)); // strict check: the salt must not be the same.
                    assertNotEqualBuffers(ctA, ctB); // strict check: the entire ciphertext must not be the same.
                    
                    // for calculating avg hamming distance between any pair of distinct messages.
                    _.zip(ctA, ctB).forEach(([byteA, byteB]) => {
                        //const hamm = hammingDistance(byteA, Math.random() < 0.5 ? byteA+1 : byteB); // for testing the test.
                        const hamm = hammingDistance(byteA, byteB);
                        distAcc += hamm;
                        numBytes++;
                    })
                })
            })

            const avgHamDist = distAcc / numBytes;
            // hamming distance check.
            //console.log('average hamming distance', avgHamDist);
            // on average, half the bits per byte should change, ie. avgHamDist should be very close to 4.
            assert.ok(Math.abs(4.0-avgHamDist) < epsillon);
        })
    })
    

    // XXX use 0xff instead of A
    // _.forEach(['AES-256-CBC-HMAC-SHA-256', 'AES-256-GCM'], (cipher) => {
    //     _.forEach([[100, ''], [10, 'A']], ([repeats, pat]) => {
    //         console.log(cipher, repeats, pat);
    //         const popcount = (v) => v == 0 ? 0 : v.toString(2).match(/1/g).length;

    //         const NUMCHARS = 10000;
    //         const EPSILLON = 0.1;
    //         it(`${cipher} should show ~50% 0s in ciphertext with a repeating pattern as cleartext (${pat.length*NUMCHARS} bytes, repeats=${repeats})`, async () => {
                
    //             let numBytes = 0;
    //             let numOneBits = 0;
    //             for (let i = 0; i < repeats; ++i) {
    //                 const msg = pat.repeat(NUMCHARS);
    //                 console.log(typeof(msg));
    //                 const ct = await sealString(msg, '', { cipher });
    //                 let acc = 0;
    //                 _.forEach(ct, (byte) => numOneBits += popcount(byte));
    //                 numBytes += ct.byteLength;    
    //             }
                
    //             const freqOneBits = numOneBits / (numBytes*8);
    //             //console.log(freqOneBits);
    //             assert(Math.abs(0.5-freqOneBits) < EPSILLON);
    //         })
    //     })
    // })
}) // seal API

// TODO bundle the tests with webpack to run in a browser.
// TODO Obtain coverage
// 
// TODO API NEGATIVE TESTS
// 
// TODO backwards compatibility vector check.
// WENCRYPTO WITH DEFAULT, DECRYPT WITH SPECIFIC AND WITH DIFFERENT, CHECK THAT ONE WORKS THE OTHER DOESN'T