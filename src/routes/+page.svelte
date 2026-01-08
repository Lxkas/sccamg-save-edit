<script lang="ts">
	import { Loader, Lock, LockOpen, Key, Download, Copy, Terminal, RotateCcw, Settings } from "@lucide/svelte";
	import { VList } from "virtua/svelte";

	// Import shadcn components
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Accordion from "$lib/components/ui/accordion";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import { Textarea } from "$lib/components/ui/textarea";
	import { toast } from "svelte-sonner";

	// --- Default Constants (for reset) ---
	const DEFAULT_AES_INFO = "aes-key-for-local-data";
	const DEFAULT_HMAC_INFO = "hmac-key-for-local-data";
	const DEFAULT_SALT_PREFIX = "PlaymeowJTSKYTIG";

	// --- State ---
	// Editable Advanced Parameters
	let aesInfoStr = DEFAULT_AES_INFO;
	let hmacInfoStr = DEFAULT_HMAC_INFO;
	let saltPrefix = DEFAULT_SALT_PREFIX;

	let masterKeyInput = "";
	let isProcessing = false;

	let decryptFile: File | null = null;
	let encryptFile: File | null = null;

	let decryptedJson = "";
	$: jsonLines = decryptedJson ? decryptedJson.split("\n") : [];

	let downloadUrl = "";
	let downloadName = "";

	// --- Utilities ---

	const hexToBytes = (hex: string) => {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
		}
		return bytes;
	};

	const stringToBytes = (str: string) => new TextEncoder().encode(str);

	// Unwraps the Registry Base64 format if needed
	const normalizeMasterKey = (input: string): Uint8Array => {
		const cleanInput = input.trim();
		// Case 1: Already Hex (64 chars)
		if (cleanInput.length === 64 && /^[0-9a-fA-F]+$/.test(cleanInput)) {
			return hexToBytes(cleanInput);
		}

		// Case 2: Base64 Wrapped (starts with user-defined prefix)
		try {
			const outerDecoded = atob(cleanInput);
			// Updated to use reactive saltPrefix [cite: 13]
			if (outerDecoded.startsWith(saltPrefix)) {
				const innerBase64 = outerDecoded.substring(saltPrefix.length);
				const rawKeyStr = atob(innerBase64); // This results in binary string
				// Convert binary string to Uint8Array
				const bytes = new Uint8Array(rawKeyStr.length);
				for (let i = 0; i < rawKeyStr.length; i++) {
					bytes[i] = rawKeyStr.charCodeAt(i);
				}
				return bytes;
			}
		} catch (e) {
			// Fall through
		}

		throw new Error("Invalid Master Key format. Must be 64-char Hex or Registry Base64.");
	};

	// --- Crypto Logic (Web Crypto API) ---

	async function hkdf(ikm: Uint8Array, length: number, infoStr: string): Promise<Uint8Array> {
		const info = stringToBytes(infoStr);
		const salt = new Uint8Array(32); // Zero-filled 32 bytes

		const keyMaterial = await window.crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
			"deriveBits"
		]);
		const derivedBits = await window.crypto.subtle.deriveBits(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: salt,
				info: info
			},
			keyMaterial,
			length * 8 // bits
		);

		return new Uint8Array(derivedBits);
	}

	async function decryptData(encryptedBytes: Uint8Array, masterKey: Uint8Array) {
		// 1. Derive Keys (Using reactive variables) [cite: 20, 21]
		const aesKeyBytes = await hkdf(masterKey, 16, aesInfoStr);
		const hmacKeyBytes = await hkdf(masterKey, 32, hmacInfoStr);

		// 2. Parse File Structure: [IV (16)][Ciphertext][HMAC (32)]
		const AES_IV_SIZE = 16;
		const HMAC_SIZE = 32;

		if (encryptedBytes.length < AES_IV_SIZE + HMAC_SIZE) throw new Error("File too short");

		const iv = encryptedBytes.slice(0, AES_IV_SIZE);
		const storedHmac = encryptedBytes.slice(encryptedBytes.length - HMAC_SIZE);
		const ciphertext = encryptedBytes.slice(AES_IV_SIZE, encryptedBytes.length - HMAC_SIZE);
		const dataToAuth = encryptedBytes.slice(0, encryptedBytes.length - HMAC_SIZE);

		// 3. Verify HMAC
		const hmacKey = await window.crypto.subtle.importKey(
			"raw",
			hmacKeyBytes as BufferSource,
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["verify"]
		);
		const isValid = await window.crypto.subtle.verify(
			"HMAC",
			hmacKey,
			storedHmac as BufferSource,
			dataToAuth as BufferSource
		);

		if (!isValid) throw new Error("HMAC verification failed! Key might be wrong or file corrupted.");

		// 4. Decrypt AES-CBC
		const aesKey = await window.crypto.subtle.importKey(
			"raw",
			aesKeyBytes as BufferSource,
			{ name: "AES-CBC" },
			false,
			["decrypt"]
		);
		const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, aesKey, ciphertext);

		return new TextDecoder().decode(decryptedBuffer);
	}

	async function encryptData(jsonStr: string, masterKey: Uint8Array) {
		// 1. Derive Keys (Using reactive variables) [cite: 28, 29]
		const aesKeyBytes = await hkdf(masterKey, 16, aesInfoStr);
		const hmacKeyBytes = await hkdf(masterKey, 32, hmacInfoStr);

		const plaintext = stringToBytes(jsonStr);

		// 2. Generate IV & Encrypt
		const iv = window.crypto.getRandomValues(new Uint8Array(16));
		const aesKey = await window.crypto.subtle.importKey(
			"raw",
			aesKeyBytes as BufferSource,
			{ name: "AES-CBC" },
			false,
			["encrypt"]
		);
		const ciphertextBuffer = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv: iv }, aesKey, plaintext);
		const ciphertext = new Uint8Array(ciphertextBuffer);

		// 3. Compute HMAC (IV + Ciphertext)
		const dataToAuth = new Uint8Array(iv.length + ciphertext.length);
		dataToAuth.set(iv);
		dataToAuth.set(ciphertext, iv.length);

		const hmacKey = await window.crypto.subtle.importKey(
			"raw",
			hmacKeyBytes as BufferSource,
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"]
		);

		const signature = await window.crypto.subtle.sign("HMAC", hmacKey, dataToAuth);
		const hmac = new Uint8Array(signature);

		// 4. Combine: [IV][Ciphertext][HMAC]
		const finalData = new Uint8Array(dataToAuth.length + hmac.length);
		finalData.set(dataToAuth);
		finalData.set(hmac, dataToAuth.length);

		return finalData;
	}

	// --- Handlers ---

	const resetDefaults = () => {
		aesInfoStr = DEFAULT_AES_INFO;
		hmacInfoStr = DEFAULT_HMAC_INFO;
		saltPrefix = DEFAULT_SALT_PREFIX;
		toast.success("Parameters reset to default.");
	};

	const handleDecrypt = async () => {
		if (!decryptFile || !masterKeyInput) {
			toast.error("Please provide both the Master Key and a .dat File.");
			return;
		}

		isProcessing = true;
		decryptedJson = "";
		if (downloadUrl) URL.revokeObjectURL(downloadUrl);
		downloadUrl = "";

		try {
			const keyBytes = normalizeMasterKey(masterKeyInput);
			const fileBuffer = await decryptFile.arrayBuffer();
			const fileBytes = new Uint8Array(fileBuffer);

			const json = await decryptData(fileBytes, keyBytes);

			JSON.parse(json);
			decryptedJson = json;

			toast.success("Decryption successful!");

			const blob = new Blob([json], { type: "application/json" });
			downloadUrl = URL.createObjectURL(blob);
			downloadName = decryptFile.name.replace(/\.dat$/, ".json");
		} catch (e: any) {
			toast.error(e.message || "Decryption failed.");
			console.error(e);
		} finally {
			isProcessing = false;
		}
	};

	const handleEncrypt = async () => {
		if (!encryptFile || !masterKeyInput) {
			toast.error("Please provide both the Master Key and a .json File.");
			return;
		}

		isProcessing = true;
		if (downloadUrl) URL.revokeObjectURL(downloadUrl);
		downloadUrl = "";

		try {
			const keyBytes = normalizeMasterKey(masterKeyInput);
			const fileText = await encryptFile.text();

			try {
				JSON.parse(fileText);
			} catch {
				throw new Error("Invalid JSON file.");
			}

			const encryptedBytes = await encryptData(fileText, keyBytes);
			toast.success("Encryption successful!");

			const blob = new Blob([encryptedBytes], { type: "application/octet-stream" });
			downloadUrl = URL.createObjectURL(blob);
			downloadName = encryptFile.name.replace(/\.json$/, ".dat");
			if (!downloadName.endsWith(".dat")) downloadName += ".dat";
		} catch (e: any) {
			toast.error(e.message || "Encryption failed.");
			console.error(e);
		} finally {
			isProcessing = false;
		}
	};

	const tryWriteClipboard = (text: string) => {
		try {
			navigator.clipboard.writeText(text);
			return true;
		} catch {
			return false;
		}
	};

	const copyCommand = () => {
		const cmd = `Get-ChildItem "HKCU:\\SOFTWARE\\Playmeow" -Recurse | Get-ItemProperty | ForEach-Object { $_.PSObject.Properties | Where-Object Name -like "*LOCAL_MASTER_KEY*" } | ForEach-Object { $s = [System.Text.Encoding]::UTF8.GetString($_.Value).Trim([char]0); [System.BitConverter]::ToString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s)).Substring(16))).Replace("-", "") }`;

		if (tryWriteClipboard(cmd)) {
			toast.success("PowerShell command copied to clipboard!");
		} else {
			toast.error("Failed to copy command to clipboard.");
		}
	};
</script>

<div class="container mx-auto max-w-3xl space-y-8 py-10">
	<div class="space-y-2 text-center">
		<h1 class="text-3xl font-bold tracking-tighter">Save File Tool</h1>
		<p class="text-muted-foreground">
			Decrypt and re-encrypt game saves for the game<br />"Sex Change Contract and Molester Girl"
			(性轉契約與痴漢少女), accurate as of version 1.4.3
		</p>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title class="flex items-center gap-2">
				<Key class="h-5 w-5" /> Master Key
			</Card.Title>
			<Card.Description>
				Required for both decryption and encryption. This key is unique to your PC.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<div class="space-y-2">
				<Label for="key">Enter Master Key (Hex or Registry String)</Label>
				<Input id="key" placeholder="43316A4DE51C8B..." bind:value={masterKeyInput} />
				<p class="text-xs text-muted-foreground">
					Supports raw 64-char Hex or the stored registry string as Hex.
				</p>
			</div>

			<div class="rounded-md bg-muted p-4 text-sm">
				<div class="mb-2 flex items-center justify-between">
					<span class="flex items-center gap-2 font-semibold"
						><Terminal class="h-4 w-4" /> How to get your key</span
					>
					<Button variant="outline" size="sm" class="h-8" onclick={copyCommand}>
						<Copy class="mr-2 h-3.5 w-3.5" /> Copy PowerShell
					</Button>
				</div>
				<code class="block rounded border bg-background p-2 font-mono text-xs break-all">
					Get-ChildItem "HKCU:\SOFTWARE\Playmeow" ... (Click copy for full command)
				</code>
			</div>

			<Accordion.Root type="single" class="w-full">
				<Accordion.Item value="advanced">
					<Accordion.Trigger class="text-sm font-medium text-muted-foreground hover:no-underline">
						<div class="flex items-center gap-2">
							<Settings class="h-4 w-4" /> Additional Parameters
						</div>
					</Accordion.Trigger>
					<Accordion.Content class="space-y-4">
						<div class="grid gap-4 md:grid-cols-2">
							<div class="space-y-2">
								<Label for="aes-info">AES Info String (HKDF)</Label>
								<Input id="aes-info" bind:value={aesInfoStr} />
							</div>
							<div class="space-y-2">
								<Label for="hmac-info">HMAC Info String (HKDF)</Label>
								<Input id="hmac-info" bind:value={hmacInfoStr} />
							</div>
							<div class="space-y-2 md:col-span-2">
								<Label for="salt-prefix">Registry Salt Prefix</Label>
								<Input id="salt-prefix" bind:value={saltPrefix} />
								<p class="text-[10px] text-muted-foreground">
									Used to detect and decode base64 registry keys.
								</p>
							</div>
						</div>
						<div class="flex justify-end">
							<Button variant="ghost" size="sm" class="h-8 text-xs" onclick={resetDefaults}>
								<RotateCcw class="mr-2 h-3 w-3" /> Reset Defaults
							</Button>
						</div>
					</Accordion.Content>
				</Accordion.Item>
			</Accordion.Root>
		</Card.Content>
	</Card.Root>

	<Tabs.Root value="decrypt" class="w-full">
		<Tabs.List class="grid w-full grid-cols-2">
			<Tabs.Trigger value="decrypt">
				<LockOpen class="mr-2 h-4 w-4" /> Decrypt
			</Tabs.Trigger>
			<Tabs.Trigger value="encrypt">
				<Lock class="mr-2 h-4 w-4" /> Encrypt
			</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="decrypt">
			<Card.Root>
				<Card.Header>
					<Card.Title>Decrypt Save File</Card.Title>
					<Card.Description>Convert a .dat file to readable JSON.</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<div class="grid w-full max-w-sm items-center gap-1.5">
						<Label for="decrypt-file">Save File (.dat)</Label>
						<Input
							id="decrypt-file"
							type="file"
							accept=".dat"
							onchange={(e) => (decryptFile = e.currentTarget.files?.[0] ?? null)}
						/>
					</div>

					{#if decryptedJson}
						<div class="space-y-2">
							<Label>Preview</Label>
							<div
								class="h-48 w-full overflow-y-auto rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-sm"
							>
								<VList data={jsonLines}>
									{#snippet children(item)}
										<div class="whitespace-pre">{item}</div>
									{/snippet}
								</VList>
							</div>
						</div>
					{/if}
				</Card.Content>
				<Card.Footer class="flex justify-between">
					<Button disabled={isProcessing || !decryptFile} onclick={handleDecrypt}>
						{#if isProcessing}
							<Loader class="mr-2 h-4 w-4 animate-spin" /> Processing
						{:else}
							Decrypt File
						{/if}
					</Button>
					{#if downloadUrl}
						<span>
							<Button
								variant="outline"
								onclick={() => {
									if (tryWriteClipboard(decryptedJson)) {
										toast.success("Decrypted JSON copied to clipboard!");
									} else {
										toast.error("Failed to copy JSON to clipboard.");
									}

									toast.success("Decrypted JSON copied to clipboard!");
								}}
							>
								<Copy class="mr-2 h-4 w-4" /> Copy JSON
							</Button>

							<Button variant="outline" href={downloadUrl} download={downloadName}>
								<Download class="mr-2 h-4 w-4" /> Download JSON
							</Button>
						</span>
					{/if}
				</Card.Footer>
			</Card.Root>
		</Tabs.Content>

		<Tabs.Content value="encrypt">
			<Card.Root>
				<Card.Header>
					<Card.Title>Encrypt Save File</Card.Title>
					<Card.Description>Convert JSON back to .dat for the game.</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<div class="grid w-full max-w-sm items-center gap-1.5">
						<Label for="encrypt-file">Edited Save (.json)</Label>
						<Input
							id="encrypt-file"
							type="file"
							accept=".json"
							onchange={(e) => (encryptFile = e.currentTarget.files?.[0] ?? null)}
						/>
					</div>
				</Card.Content>
				<Card.Footer class="flex justify-between">
					<Button disabled={isProcessing || !encryptFile} onclick={handleEncrypt}>
						{#if isProcessing}
							<Loader class="mr-2 h-4 w-4 animate-spin" /> Processing
						{:else}
							Encrypt File
						{/if}
					</Button>
					{#if downloadUrl}
						<Button variant="outline" href={downloadUrl} download={downloadName}>
							<Download class="mr-2 h-4 w-4" /> Download DAT
						</Button>
					{/if}
				</Card.Footer>
			</Card.Root>
		</Tabs.Content>
	</Tabs.Root>
</div>
