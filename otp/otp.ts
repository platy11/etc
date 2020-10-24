// Copyright 2020, Max E.
// Released under the terms of the ISC License.

import { encode as encodeBase32, decode as decodeBase32 } from './base32'

export async function verifyTotp(
    secret: string,
    input: number,
    periodRange: number
): Promise<boolean> {
    let key = await decodeKey(secret)
    let now = Date.now()
    for (let i = 0; i < periodRange; i++) {
        if (
            await totp(key, now, i) === input ||
            i != 0 && await totp(key, now, -i) === input
        ) {
            return true
        }
    }
    return false
}

export async function verifyHotp(
    secret: string,
    input: number,
    c: number
): Promise<boolean> {
    let k = await decodeKey(secret)
    return await hotp(k, c) === input
}

export async function decodeKey(secret: string): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        'raw',
        decodeBase32(secret).buffer,
        {
            name: 'HMAC',
            hash: 'SHA-1'
        },
        false,
        ['sign']
    )
}

export async function totp(k: CryptoKey, time: number, offset: number): Promise<number> {
    let c = time / 30000 + offset
    return hotp(k, c)
}

export async function hotp(k: CryptoKey, c: number): Promise<number> {
    let hmac = new Uint8Array(await crypto.subtle.sign(
        'HMAC',
        k,
        // Convert c to an 8 byte number, per the HOTP specification (RFC 4226).
        // JS numbers are only 53 bits, so zero the first byte and mask the second
        // with 0x1f
        new Uint8Array([
            0,
            (c & 0x001f000000000000) >> 48,
            (c & 0x0000ff0000000000) >> 40,
            (c & 0x000000ff00000000) >> 32,
            (c & 0x00000000ff000000) >> 24,
            (c & 0x0000000000ff0000) >> 16,
            (c & 0x000000000000ff00) >>  8,
            (c & 0x00000000000000ff)
        ])
    ))
    let offset = hmac[19] & 0x0f
    // Convert 4 bytes starting at the offset to a number
    let bincode =
        (hmac[offset]     & 0x7f) << 24 |
        (hmac[offset + 1] & 0xff) << 16 |
        (hmac[offset + 2] & 0xff) <<  8 |
        (hmac[offset + 3] & 0xff)
    return bincode % 10 ** 6
}

export async function generateTotpSecret(): Promise<string> {
    let key = await crypto.subtle.generateKey({
        name: 'HMAC',
        hash: {
            name: 'SHA-1'
        }
    }, true, [])
    let bytes = await crypto.subtle.exportKey('raw', key)
    return encodeBase32(new Uint8Array(bytes))
}

export function googleAuthenticatorTotpURI(
    username: string,
    secret: string,
    issuer: string
): string {
    let params = new URLSearchParams()
    params.set('secret', secret)
    params.set('issuer', issuer)
    params.set('algorithm', 'SHA1')
    params.set('digits', '6')
    params.set('period', '30')
    return `otpauth://totp/${issuer}:${username}?${params.toString()}`
}