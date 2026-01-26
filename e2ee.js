/*
 * e2ee.js — Client-side E2EE utilities (PBKDF2 + AES-GCM)
 * Usage:
 *  - Encrypt: const pkg = await E2EE.encryptObject(obj, passphrase);
 *  - Decrypt: const obj = await E2EE.decryptObject(pkg, passphrase);
 * Notes:
 *  - Uses Web Crypto API. PBKDF2 iterations set to 200000 by default.
 *  - Returns base64-encoded fields for easy storage in Firestore.
 */

const E2EE = (function () {
    const DEFAULT_PBKDF2_ITERS = 200000; // increase as needed
    const SALT_BYTES = 16;
    const IV_BYTES = 12; // recommended for AES-GCM

    function toBase64(u8) {
        return btoa(String.fromCharCode(...u8));
    }

    function fromBase64(s) {
        const bin = atob(s);
        const len = bin.length;
        const u8 = new Uint8Array(len);
        for (let i = 0; i < len; i++) u8[i] = bin.charCodeAt(i);
        return u8;
    }

    function randomBytes(n) {
        const buf = new Uint8Array(n);
        crypto.getRandomValues(buf);
        return buf;
    }

    async function deriveKeyPBKDF2(passphrase, saltBase64, iterations = DEFAULT_PBKDF2_ITERS) {
        const enc = new TextEncoder();
        const passKey = await crypto.subtle.importKey(
            'raw',
            enc.encode(passphrase),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        const salt = fromBase64(saltBase64);

        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
            passKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptObject(obj, passphrase) {
        const salt = randomBytes(SALT_BYTES);
        const saltB = toBase64(salt);
        const key = await deriveKeyPBKDF2(passphrase, saltB);

        const iv = randomBytes(IV_BYTES);
        const enc = new TextEncoder();
        const plain = enc.encode(JSON.stringify(obj));

        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);

        return {
            version: 'v1',
            encrypted: true,
            ciphertext: toBase64(new Uint8Array(ct)),
            nonce: toBase64(iv),
            salt: saltB,
            kdf: 'PBKDF2',
            kdfIterations: DEFAULT_PBKDF2_ITERS
        };
    }

    async function decryptObject(pkg, passphrase) {
        if (!pkg || !pkg.encrypted) throw new Error('Package is not encrypted');
        if (!pkg.salt || !pkg.nonce || !pkg.ciphertext) throw new Error('Malformed package');

        const key = await deriveKeyPBKDF2(passphrase, pkg.salt, pkg.kdfIterations || DEFAULT_PBKDF2_ITERS);
        const iv = fromBase64(pkg.nonce);
        const ct = fromBase64(pkg.ciphertext);

        const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        const dec = new TextDecoder();
        return JSON.parse(dec.decode(plainBuf));
    }

    return {
        deriveKeyPBKDF2,
        encryptObject,
        decryptObject,
        _internal: { toBase64, fromBase64 }
    };
})();

// Expose to global for easy use from index.html
if (typeof window !== 'undefined') window.E2EE = E2EE;
