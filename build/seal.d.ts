export interface SealOptions {
    kdfRounds?: number;
    cipher?: string;
}
export declare function sealValue(value: any, passphrase: string | Uint8Array, opts?: SealOptions): Promise<Uint8Array<ArrayBuffer>>;
export declare function sealString(data: string, passphrase: string | Uint8Array, opts?: SealOptions): Promise<Uint8Array<ArrayBuffer>>;
export declare function sealBuffer(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions): Promise<Uint8Array<ArrayBuffer>>;
export declare function unsealValue(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions): Promise<any>;
export declare function unsealString(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions): Promise<string>;
export declare function unsealBuffer(data: Uint8Array, passphrase: string | Uint8Array, opts?: SealOptions): Promise<ArrayBuffer>;
//# sourceMappingURL=seal.d.ts.map