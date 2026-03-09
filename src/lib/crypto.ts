export const DEFAULT_AES_INFO = "aes-key-for-local-data";
export const DEFAULT_HMAC_INFO = "hmac-key-for-local-data";
export const DEFAULT_SALT_PREFIX = "PlaymeowJTSKYTIG";

const AES_IV_SIZE = 16;
const HMAC_SIZE = 32;

export function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

export function stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

// unwraps the registry Base64 format if needed
export function normalizeMasterKey(input: string, saltPrefix = DEFAULT_SALT_PREFIX): Uint8Array {
    const cleanInput = input.trim();

    // case 1: already hex (64 chars)
    if (cleanInput.length === 64 && /^[0-9a-fA-F]+$/.test(cleanInput)) {
        return hexToBytes(cleanInput);
    }

    // case 2: base64 wrapped (starts with user-defined prefix)
    try {
        const outerDecoded = atob(cleanInput);
        if (outerDecoded.startsWith(saltPrefix)) {
            const innerBase64 = outerDecoded.substring(saltPrefix.length);
            const rawKeyStr = atob(innerBase64);
            const bytes = new Uint8Array(rawKeyStr.length);
            for (let i = 0; i < rawKeyStr.length; i++) {
                bytes[i] = rawKeyStr.charCodeAt(i);
            }
            return bytes;
        }
    } catch {
        // fall through
    }

    throw new Error("Invalid Master Key format. Must be 64-char Hex or Registry Base64.");
}

export async function hkdf(ikm: Uint8Array, length: number, infoStr: string): Promise<Uint8Array> {
    const info = stringToBytes(infoStr);
    const salt = new Uint8Array(32); // zero-filled 32 bytes

    const keyMaterial = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: info as BufferSource },
        keyMaterial,
        length * 8,
    );

    return new Uint8Array(derivedBits);
}

export async function decryptData(
    encryptedBytes: Uint8Array,
    masterKey: Uint8Array,
    aesInfoStr = DEFAULT_AES_INFO,
    hmacInfoStr = DEFAULT_HMAC_INFO,
): Promise<string> {
    // 1. derive keys
    const aesKeyBytes = await hkdf(masterKey, 16, aesInfoStr);
    const hmacKeyBytes = await hkdf(masterKey, 32, hmacInfoStr);

    // 2. parse file structure: [IV (16)][Ciphertext][HMAC (32)]
    if (encryptedBytes.length < AES_IV_SIZE + HMAC_SIZE) throw new Error("File too short");

    const iv = encryptedBytes.slice(0, AES_IV_SIZE);
    const storedHmac = encryptedBytes.slice(encryptedBytes.length - HMAC_SIZE);
    const ciphertext = encryptedBytes.slice(AES_IV_SIZE, encryptedBytes.length - HMAC_SIZE);
    const dataToAuth = encryptedBytes.slice(0, encryptedBytes.length - HMAC_SIZE);

    // 3. verify HMAC
    const hmacKey = await crypto.subtle.importKey(
        "raw",
        hmacKeyBytes as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
    );
    const isValid = await crypto.subtle.verify(
        "HMAC",
        hmacKey,
        storedHmac as BufferSource,
        dataToAuth as BufferSource,
    );

    if (!isValid) throw new Error("HMAC verification failed! Key might be wrong or file corrupted.");

    // 4. decrypt AES-CBC
    const aesKey = await crypto.subtle.importKey(
        "raw",
        aesKeyBytes as BufferSource,
        { name: "AES-CBC" },
        false,
        ["decrypt"],
    );
    const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ciphertext);

    return new TextDecoder().decode(decryptedBuffer);
}

export async function encryptData(
    jsonStr: string,
    masterKey: Uint8Array,
    aesInfoStr = DEFAULT_AES_INFO,
    hmacInfoStr = DEFAULT_HMAC_INFO,
): Promise<Uint8Array> {
    // 1. derive keys
    const aesKeyBytes = await hkdf(masterKey, 16, aesInfoStr);
    const hmacKeyBytes = await hkdf(masterKey, 32, hmacInfoStr);

    const plaintext = stringToBytes(jsonStr);

    // 2. generate IV & encrypt
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.importKey(
        "raw",
        aesKeyBytes as BufferSource,
        { name: "AES-CBC" },
        false,
        ["encrypt"],
    );
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        aesKey,
        plaintext as BufferSource,
    );
    const ciphertext = new Uint8Array(ciphertextBuffer);

    // 3. compute HMAC (IV + Ciphertext)
    const dataToAuth = new Uint8Array(iv.length + ciphertext.length);
    dataToAuth.set(iv);
    dataToAuth.set(ciphertext, iv.length);

    const hmacKey = await crypto.subtle.importKey(
        "raw",
        hmacKeyBytes as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );

    const signature = await crypto.subtle.sign("HMAC", hmacKey, dataToAuth);
    const hmac = new Uint8Array(signature);

    // 4. combine: [IV][Ciphertext][HMAC]
    const finalData = new Uint8Array(dataToAuth.length + hmac.length);
    finalData.set(dataToAuth);
    finalData.set(hmac, dataToAuth.length);

    return finalData;
}
