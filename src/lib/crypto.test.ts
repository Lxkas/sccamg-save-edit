import { describe, it, expect } from "vitest";
import {
    hexToBytes,
    stringToBytes,
    normalizeMasterKey,
    hkdf,
    encryptData,
    decryptData,
    DEFAULT_AES_INFO,
    DEFAULT_HMAC_INFO,
    DEFAULT_SALT_PREFIX,
} from "./crypto";

// a fixed 32-byte master key (64 hex chars) for deterministic tests
const TEST_KEY_HEX = "43316a4de51c8b7f0123456789abcdef43316a4de51c8b7f0123456789abcdef";
const TEST_KEY_BYTES = hexToBytes(TEST_KEY_HEX);

// ── hexToBytes ──────────────────────────────────────────────────────────

describe("hexToBytes", () => {
    it("converts a simple hex string", () => {
        expect(hexToBytes("0102030405")).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    it("converts 00 to [0]", () => {
        expect(hexToBytes("00")).toEqual(new Uint8Array([0]));
    });

    it("converts ff to [255]", () => {
        expect(hexToBytes("ff")).toEqual(new Uint8Array([255]));
    });

    it("converts FF to [255] (uppercase)", () => {
        expect(hexToBytes("FF")).toEqual(new Uint8Array([255]));
    });

    it("handles empty string", () => {
        expect(hexToBytes("")).toEqual(new Uint8Array([]));
    });

    it("converts a full 32-byte key", () => {
        const bytes = hexToBytes(TEST_KEY_HEX);
        expect(bytes.length).toBe(32);
        expect(bytes[0]).toBe(0x43);
        expect(bytes[31]).toBe(0xef);
    });

    it("handles mixed case", () => {
        expect(hexToBytes("aAbBcC")).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
    });
});

// ── stringToBytes ───────────────────────────────────────────────────────

describe("stringToBytes", () => {
    it("encodes ASCII text", () => {
        const bytes = stringToBytes("hello");
        expect(bytes).toEqual(new Uint8Array([104, 101, 108, 108, 111]));
    });

    it("encodes empty string", () => {
        expect(stringToBytes("")).toEqual(new Uint8Array([]));
    });

    it("encodes unicode characters", () => {
        const bytes = stringToBytes("é");
        // UTF-8 encoding of é is 0xC3 0xA9
        expect(bytes).toEqual(new Uint8Array([0xc3, 0xa9]));
    });

    it("encodes multi-byte CJK characters", () => {
        const bytes = stringToBytes("性");
        // UTF-8 encoding of 性 (U+6027) is 0xE6 0x80 0xA7
        expect(bytes).toEqual(new Uint8Array([0xe6, 0x80, 0xa7]));
    });
});

// ── normalizeMasterKey ──────────────────────────────────────────────────

describe("normalizeMasterKey", () => {
    it("accepts a valid 64-char lowercase hex string", () => {
        const bytes = normalizeMasterKey(TEST_KEY_HEX);
        expect(bytes.length).toBe(32);
        expect(bytes[0]).toBe(0x43);
    });

    it("accepts a valid 64-char uppercase hex string", () => {
        const bytes = normalizeMasterKey(TEST_KEY_HEX.toUpperCase());
        expect(bytes.length).toBe(32);
        expect(bytes).toEqual(hexToBytes(TEST_KEY_HEX));
    });

    it("accepts mixed case hex", () => {
        const mixed = "43316A4de51C8b7f0123456789AbCdEf43316a4DE51c8B7F0123456789aBcDeF";
        const bytes = normalizeMasterKey(mixed);
        expect(bytes.length).toBe(32);
    });

    it("trims whitespace", () => {
        const padded = `  ${TEST_KEY_HEX}  `;
        const bytes = normalizeMasterKey(padded);
        expect(bytes).toEqual(TEST_KEY_BYTES);
    });

    it("trims newlines and tabs", () => {
        const padded = `\n\t${TEST_KEY_HEX}\t\n`;
        const bytes = normalizeMasterKey(padded);
        expect(bytes).toEqual(TEST_KEY_BYTES);
    });

    it("rejects a hex string that is too short", () => {
        expect(() => normalizeMasterKey("abcdef1234")).toThrow("Invalid Master Key format");
    });

    it("rejects a hex string that is too long", () => {
        expect(() => normalizeMasterKey(TEST_KEY_HEX + "aa")).toThrow("Invalid Master Key format");
    });

    it("rejects 64 chars with non-hex characters", () => {
        const invalid = "g" + TEST_KEY_HEX.slice(1);
        expect(() => normalizeMasterKey(invalid)).toThrow("Invalid Master Key format");
    });

    it("rejects completely random input", () => {
        expect(() => normalizeMasterKey("not a valid key at all!")).toThrow("Invalid Master Key format");
    });

    it("rejects empty input", () => {
        expect(() => normalizeMasterKey("")).toThrow("Invalid Master Key format");
    });

    it("accepts a valid base64 registry string", () => {
        // construct a valid registry string: base64(saltPrefix + base64(rawKeyBytes))
        const rawKeyBinary = String.fromCharCode(...TEST_KEY_BYTES);
        const innerBase64 = btoa(rawKeyBinary);
        const outer = DEFAULT_SALT_PREFIX + innerBase64;
        const registryValue = btoa(outer);

        const bytes = normalizeMasterKey(registryValue);
        expect(bytes).toEqual(TEST_KEY_BYTES);
    });

    it("accepts a registry string with custom salt prefix", () => {
        const customPrefix = "CustomPrefix1234";
        const rawKeyBinary = String.fromCharCode(...TEST_KEY_BYTES);
        const innerBase64 = btoa(rawKeyBinary);
        const outer = customPrefix + innerBase64;
        const registryValue = btoa(outer);

        const bytes = normalizeMasterKey(registryValue, customPrefix);
        expect(bytes).toEqual(TEST_KEY_BYTES);
    });

    it("rejects base64 with wrong salt prefix", () => {
        const rawKeyBinary = String.fromCharCode(...TEST_KEY_BYTES);
        const innerBase64 = btoa(rawKeyBinary);
        const outer = "WrongPrefix12345" + innerBase64;
        const registryValue = btoa(outer);

        // default salt prefix won't match
        expect(() => normalizeMasterKey(registryValue)).toThrow("Invalid Master Key format");
    });
});

// ── hkdf ────────────────────────────────────────────────────────────────

describe("hkdf", () => {
    it("derives a 16-byte key", async () => {
        const derived = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        expect(derived.length).toBe(16);
        expect(derived).toBeInstanceOf(Uint8Array);
    });

    it("derives a 32-byte key", async () => {
        const derived = await hkdf(TEST_KEY_BYTES, 32, DEFAULT_HMAC_INFO);
        expect(derived.length).toBe(32);
    });

    it("is deterministic (same inputs → same output)", async () => {
        const a = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        const b = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        expect(a).toEqual(b);
    });

    it("different info strings produce different keys", async () => {
        const aesKey = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        const hmacKey = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_HMAC_INFO);
        expect(aesKey).not.toEqual(hmacKey);
    });

    it("different master keys produce different derived keys", async () => {
        const otherKey = new Uint8Array(32);
        otherKey.fill(0xaa);

        const a = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        const b = await hkdf(otherKey, 16, DEFAULT_AES_INFO);
        expect(a).not.toEqual(b);
    });

    it("different lengths produce differently-sized outputs", async () => {
        const short = await hkdf(TEST_KEY_BYTES, 16, DEFAULT_AES_INFO);
        const long = await hkdf(TEST_KEY_BYTES, 32, DEFAULT_AES_INFO);
        expect(short.length).toBe(16);
        expect(long.length).toBe(32);
        // the first 16 bytes of the 32-byte derivation should match the 16-byte derivation
        // (HKDF is a PRF, and with same T(1) block this holds)
        expect(long.slice(0, 16)).toEqual(short);
    });
});

// ── encrypt / decrypt round-trip ────────────────────────────────────────

describe("encryptData / decryptData round-trip", () => {
    it("round-trips a simple JSON string", async () => {
        const original = '{"hello":"world"}';
        const encrypted = await encryptData(original, TEST_KEY_BYTES);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES);
        expect(decrypted).toBe(original);
    });

    it("round-trips a complex JSON with unicode", async () => {
        const original = JSON.stringify({
            name: "性轉契約與痴漢少女",
            money: 99999,
            unlock: true,
            items: [1, 2, 3],
            nested: { deep: { value: "café" } },
        });
        const encrypted = await encryptData(original, TEST_KEY_BYTES);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES);
        expect(decrypted).toBe(original);
    });

    it("round-trips an empty JSON object", async () => {
        const original = "{}";
        const encrypted = await encryptData(original, TEST_KEY_BYTES);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES);
        expect(decrypted).toBe(original);
    });

    it("round-trips a large payload", async () => {
        const largeObj: Record<string, number> = {};
        for (let i = 0; i < 1000; i++) {
            largeObj[`key_${i}`] = i;
        }
        const original = JSON.stringify(largeObj);
        const encrypted = await encryptData(original, TEST_KEY_BYTES);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES);
        expect(decrypted).toBe(original);
    });

    it("round-trips with custom info strings", async () => {
        const customAes = "custom-aes-info";
        const customHmac = "custom-hmac-info";
        const original = '{"custom":true}';

        const encrypted = await encryptData(original, TEST_KEY_BYTES, customAes, customHmac);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES, customAes, customHmac);
        expect(decrypted).toBe(original);
    });

    it("round-trips plain text (not just JSON)", async () => {
        const original = "This is just plain text, not JSON.";
        const encrypted = await encryptData(original, TEST_KEY_BYTES);
        const decrypted = await decryptData(encrypted, TEST_KEY_BYTES);
        expect(decrypted).toBe(original);
    });
});

// ── encryptData output format ───────────────────────────────────────────

describe("encryptData output format", () => {
    it("produces output with correct structure [IV 16][Ciphertext][HMAC 32]", async () => {
        const encrypted = await encryptData("{}", TEST_KEY_BYTES);
        // minimum size: 16 (IV) + 16 (at least one AES block) + 32 (HMAC) = 64
        expect(encrypted.length).toBeGreaterThanOrEqual(64);
    });

    it("output length is at least IV + one AES block + HMAC", async () => {
        const encrypted = await encryptData("x", TEST_KEY_BYTES);
        // AES-CBC with PKCS7 padding: 1 byte → 16 bytes ciphertext
        // total = 16 (IV) + 16 (ciphertext) + 32 (HMAC) = 64
        expect(encrypted.length).toBe(64);
    });

    it("ciphertext length increases with input (block aligned)", async () => {
        const short = await encryptData("a", TEST_KEY_BYTES);
        // 17 bytes plaintext → 32 bytes ciphertext (2 AES blocks with padding)
        const longer = await encryptData("a".repeat(17), TEST_KEY_BYTES);
        expect(longer.length).toBeGreaterThan(short.length);
    });

    it("different encryptions of the same plaintext produce different output (random IV)", async () => {
        const original = '{"test":1}';
        const enc1 = await encryptData(original, TEST_KEY_BYTES);
        const enc2 = await encryptData(original, TEST_KEY_BYTES);

        // IVs should differ (first 16 bytes)
        const iv1 = enc1.slice(0, 16);
        const iv2 = enc2.slice(0, 16);
        // technically could match with 2^-128 probability, but effectively never
        expect(iv1).not.toEqual(iv2);

        // but both should decrypt to the same plaintext
        const dec1 = await decryptData(enc1, TEST_KEY_BYTES);
        const dec2 = await decryptData(enc2, TEST_KEY_BYTES);
        expect(dec1).toBe(original);
        expect(dec2).toBe(original);
    });
});

// ── decryptData error handling ──────────────────────────────────────────

describe("decryptData error handling", () => {
    it("throws on file that is too short", async () => {
        const tooShort = new Uint8Array(47); // less than 16 + 32 = 48
        await expect(decryptData(tooShort, TEST_KEY_BYTES)).rejects.toThrow("File too short");
    });

    it("throws on exactly minimum length but invalid content", async () => {
        const minimal = new Uint8Array(48); // 16 IV + 0 ciphertext + 32 HMAC
        await expect(decryptData(minimal, TEST_KEY_BYTES)).rejects.toThrow("HMAC verification failed");
    });

    it("throws on wrong master key", async () => {
        const original = '{"data":"secret"}';
        const encrypted = await encryptData(original, TEST_KEY_BYTES);

        const wrongKey = new Uint8Array(32);
        wrongKey.fill(0xff);

        await expect(decryptData(encrypted, wrongKey)).rejects.toThrow("HMAC verification failed");
    });

    it("throws on corrupted ciphertext (flipped byte)", async () => {
        const encrypted = await encryptData('{"ok":true}', TEST_KEY_BYTES);
        // flip a byte in the ciphertext region (after IV, before HMAC)
        const corrupted = new Uint8Array(encrypted);
        corrupted[20] ^= 0xff;

        await expect(decryptData(corrupted, TEST_KEY_BYTES)).rejects.toThrow("HMAC verification failed");
    });

    it("throws on corrupted HMAC (flipped byte)", async () => {
        const encrypted = await encryptData('{"ok":true}', TEST_KEY_BYTES);
        const corrupted = new Uint8Array(encrypted);
        // flip last byte (in HMAC region)
        corrupted[corrupted.length - 1] ^= 0xff;

        await expect(decryptData(corrupted, TEST_KEY_BYTES)).rejects.toThrow("HMAC verification failed");
    });

    it("throws on corrupted IV (flipped byte)", async () => {
        const encrypted = await encryptData('{"ok":true}', TEST_KEY_BYTES);
        const corrupted = new Uint8Array(encrypted);
        // flip first byte (in IV region)
        corrupted[0] ^= 0xff;

        await expect(decryptData(corrupted, TEST_KEY_BYTES)).rejects.toThrow("HMAC verification failed");
    });

    it("throws when info strings don't match between encrypt and decrypt", async () => {
        const encrypted = await encryptData('{"mismatch":1}', TEST_KEY_BYTES, "aes-info-a", "hmac-info-a");
        await expect(decryptData(encrypted, TEST_KEY_BYTES, "aes-info-b", "hmac-info-b")).rejects.toThrow(
            "HMAC verification failed",
        );
    });

    it("throws when only AES info differs", async () => {
        const encrypted = await encryptData('{"x":1}', TEST_KEY_BYTES, "aes-a", DEFAULT_HMAC_INFO);
        // same HMAC info means HMAC will pass, but decryption will produce garbage → may throw or produce bad output
        // actually: HMAC is computed over IV+ciphertext with the HMAC key. if only AES info differs,
        // the HMAC key is the same, so HMAC will pass. but decryption with wrong AES key → padding error
        await expect(decryptData(encrypted, TEST_KEY_BYTES, "aes-b", DEFAULT_HMAC_INFO)).rejects.toThrow();
    });
});

// ── integration: normalizeMasterKey → encrypt → decrypt ─────────────────

describe("integration: full flow with normalizeMasterKey", () => {
    it("works with hex key input", async () => {
        const keyBytes = normalizeMasterKey(TEST_KEY_HEX);
        const original = '{"save":[1,2,3]}';
        const encrypted = await encryptData(original, keyBytes);
        const decrypted = await decryptData(encrypted, keyBytes);
        expect(decrypted).toBe(original);
    });

    it("works with base64 registry key input", async () => {
        const rawKeyBinary = String.fromCharCode(...TEST_KEY_BYTES);
        const innerBase64 = btoa(rawKeyBinary);
        const outer = DEFAULT_SALT_PREFIX + innerBase64;
        const registryValue = btoa(outer);

        const keyBytes = normalizeMasterKey(registryValue);
        const original = '{"money":99999}';
        const encrypted = await encryptData(original, keyBytes);
        const decrypted = await decryptData(encrypted, keyBytes);
        expect(decrypted).toBe(original);
    });

    it("hex and registry formats produce the same key bytes", () => {
        const rawKeyBinary = String.fromCharCode(...TEST_KEY_BYTES);
        const innerBase64 = btoa(rawKeyBinary);
        const outer = DEFAULT_SALT_PREFIX + innerBase64;
        const registryValue = btoa(outer);

        const fromHex = normalizeMasterKey(TEST_KEY_HEX);
        const fromRegistry = normalizeMasterKey(registryValue);
        expect(fromHex).toEqual(fromRegistry);
    });
});
