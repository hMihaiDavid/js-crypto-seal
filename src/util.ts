// XXX base64decode base64encode hexEncode hexDecode
export function utf8Encode(str: string): Uint8Array {
    return (new TextEncoder()).encode(str);
}

export function utf8Decode(data: Uint8Array): string {
    return (new TextDecoder()).decode(data);
}