<script lang="ts">
	import {
		Loader,
		Lock,
		LockOpen,
		Key,
		Download,
		Copy,
		Terminal,
		RotateCcw,
		Settings,
		CircleQuestionMark,
		BookOpen
	} from "@lucide/svelte";
	import MarkdownContent from "$lib/components/markdown-content.svelte";
	import {
		DEFAULT_AES_INFO,
		DEFAULT_HMAC_INFO,
		DEFAULT_SALT_PREFIX,
		normalizeMasterKey,
		decryptData,
		encryptData
	} from "$lib/crypto";
	import { VList } from "virtua/svelte";

	// Import shadcn components
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Accordion from "$lib/components/ui/accordion";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import { toast } from "svelte-sonner";

	// --- Guide Sections ---
	const guideSections = [
		{
			id: "before-you-start",
			title: "Before You Start",
			content: `> **Warning:** Always back up your save files before making any changes. If something goes wrong, you can restore the backup and try again. Editing saves incorrectly can break your progress.

## What you'll need

- A **Windows PC** with the game installed
- The game must have been **launched at least once** (this creates the save files and registry key)
- A text editor, **Notepad** works, but we recommend a free editor like [Visual Studio Code](https://code.visualstudio.com/) or [Notepad++](https://notepad-plus-plus.org/) for easier reading

> **Tip:** The whole process takes about 5-10 minutes your first time. After that, it's much faster.

## How the process works

1. You get your **Master Key**, a unique code tied to your PC that the game uses to lock your saves
2. You **decrypt** (unlock) the save file into a readable format called JSON
3. You **edit** the JSON to change whatever you want
4. You **encrypt** (re-lock) the JSON back into the format the game expects
5. You **replace** the original save file with your edited one`
		},
		{
			id: "getting-master-key",
			title: "Step 1: Getting Your Master Key",
			content: `Your **Master Key** is a unique code that the game generates on your PC. It's used to lock (encrypt) and unlock (decrypt) your save files. Without it, the tool can't read or write your saves.

There are two ways to get it. Try the easy way first.

## Easy way: PowerShell command

PowerShell is a program that's already installed on every Windows PC. It lets you run commands to do things automatically.

1. On this page, find the **"How to get your key"** box and click the **Copy PowerShell** button, this copies a command to your clipboard
2. Press **Win + R** on your keyboard (hold the Windows key and tap R). A small "Run" box appears
3. Type \`powershell\` and press **Enter**. A blue/black window opens. This is PowerShell
4. **Right-click** anywhere in the PowerShell window, this pastes the command you copied
5. Press **Enter** to run it
6. A long string of letters and numbers appears, this is your Master Key
7. Select it (click and drag, or triple-click), then **right-click** to copy it
8. Paste it into the **Master Key** field on this page

> **Tip:** The key looks something like \`43316A4DE51C8B7F...\`, it's exactly 64 characters long. If you see something much shorter or longer, something went wrong.

## Manual way: Registry Editor

If PowerShell didn't work, you can find the key directly in the Windows Registry- a database where Windows and apps store settings.

1. Press **Win + R**, type \`regedit\`, and press **Enter**. Click **Yes** if asked for permission
2. In the left sidebar, navigate to this path by clicking each folder:
   \`HKEY_CURRENT_USER\\SOFTWARE\\Playmeow\\性轉契約與痴漢少女\`
3. In the right panel, look for an entry whose name contains \`__LOCAL_MASTER_KEY_V2___h\`
4. Double-click it to open it
5. Copy the value in the **"Value data"** field
6. Paste it into the **Master Key** field on this page and the tool will decode it automatically

> **Tip:** If you can't find the Playmeow folder, make sure you've launched the game at least once. The registry key is created on first launch.`
		},
		{
			id: "decrypting-save",
			title: "Step 2: Decrypting Your Save",
			content: `Now that you have your Master Key, you need to find your save file and decrypt (unlock) it.

## Finding your save files

Your save files are stored in a hidden folder. Here's how to get there:

1. Press **Win + R**, paste this path, and press **Enter**:
   \`%UserProfile%\\AppData\\LocalLow\\Playmeow\\性轉契約與痴漢少女\`
2. A File Explorer window opens showing your save files. They have the \`.dat\` extension

> **Tip:** If the folder is empty or doesn't exist, the AppData folder might be hidden. In File Explorer, click **View** at the top, then check **Hidden items** to show hidden folders.

You'll see one or more \`.dat\` files. Each file contains **all** save slots (global auto-save + manual slots 1-9), game settings, and CG unlock data in a single encrypted blob.

## Decrypting

1. On this page, paste your **Master Key** into the key field (if you haven't already)
2. Switch to the **Decrypt** tab
3. Click **Choose File** and select the \`.dat\` save file you want to edit
4. Click **Decrypt File**
5. If successful, you'll see a preview of the save data as JSON
6. Click **Download JSON** to save the decrypted file to your computer

> **Warning:** Keep the original \`.dat\` file as a backup! Don't delete it until you've confirmed your edited save works in the game.`
		},
		{
			id: "editing-json",
			title: "Step 3: Editing the JSON",
			content: `The decrypted save is in a format called **JSON** (JavaScript Object Notation). It's a way of storing data that's both human-readable and machine-readable.

## What JSON looks like

Here's a tiny example of what JSON looks like:

\`\`\`json
{
  "name": "Alice",
  "money": 1200,
  "unlock": true
}
\`\`\`

- Values in **quotes** are text: \`"Alice"\`
- Numbers don't have quotes: \`1200\`
- \`true\` / \`false\` are boolean (on/off) values, no quotes
- Lists are in **square brackets**: \`[1, 2, 3]\`
- Everything is wrapped in **curly braces**: \`{ }\`

## Save file structure

The save file has four top-level sections:

- **\`env\`**: game settings (language, volume, resolution, playtime, etc.)
- **\`cg\`**: an array of all CG (gallery) scenes. Each CG has an \`"unlock"\` field that is \`true\` or \`false\`
- **\`game_log\`**: internal log data
- **\`save\`**: an array of save slots (\`"key": "global"\` for the auto-save, \`"key": "1"\` through \`"key": "9"\` for manual slots). Each slot contains an \`app.db\` object with game state like \`base\` (protagonist stats including \`money\`), \`role\` (character stats like \`hp\`, \`sp\`, \`tp\`), and various \`db_table_*\` / \`db_field_*\` entries for game flags

> **Tip:** The field names like \`db_field_1663134995686\` are auto-generated IDs, they're not human-readable, but each one controls a specific game variable. You'll need to experiment or compare saves to figure out which is which.

## How to edit

1. Open the downloaded \`.json\` file in your text editor
2. Use **Ctrl + F** (Find) to search for the value you want to change
3. Edit the value. For example, change \`"money": 0\` to \`"money": 99999\`
4. Save the file (**Ctrl + S**)

## Common edits

- **Unlock all CGs**: search for \`"unlock": false\` and replace all with \`"unlock": true\` (there are up to 42 CG entries in the \`cg\` array)
- **Edit money**: in a save slot's \`app.db.base[0]\`, find the \`"money"\` field and change its value
- **Edit character stats**: in a save slot's \`app.db.role\`, each character has \`hp\`, \`sp\`, and \`tp\` fields

> **Warning:** Each save slot is independent. If you edit slot \`"key": "1"\`, only that slot is affected. The \`"key": "global"\` slot is the auto-save, edit it too if needed.

## Rules to follow

> **Warning:** Breaking these rules will corrupt the save file.

- **Don't delete quotes** around text values, \`"Alice"\` is correct, \`Alice\` is not
- **Don't remove commas** between values, each line (except the last in a group) needs a comma
- **Don't delete curly braces** \`{ }\` or **square brackets** \`[ ]\`, they define the structure
- **Don't change key names** (the part before the colon), only change the values
- Boolean values must be exactly \`true\` or \`false\` (lowercase, no quotes)

> **Tip:** If you're unsure about your edit, keep a copy of the original JSON open in another window to compare.`
		},
		{
			id: "encrypting-replacing",
			title: "Step 4: Re-encrypting & Replacing",
			content: `Once you've edited the JSON, you need to encrypt it back into the format the game can read, then replace the original file.

## Encrypting

1. On this page, make sure your **Master Key** is still entered
2. Switch to the **Encrypt** tab
3. Click **Choose File** and select your edited \`.json\` file
4. Click **Encrypt File**
5. Click **Download DAT** to save the encrypted file

## Replacing the save file

> **Warning:** Make sure the game is **completely closed** before replacing the file. If the game is running, it may overwrite your changes when it saves.

1. Press **Win + R**, paste this path, and press **Enter**:
   \`%UserProfile%\\AppData\\LocalLow\\Playmeow\\性轉契約與痴漢少女\`
2. Find the original \`.dat\` file you decrypted earlier
3. **Rename** the original file as a backup (e.g., rename \`SaveData0.dat\` to \`SaveData0_backup.dat\`)
4. Copy your newly encrypted \`.dat\` file into this folder
5. **Rename** the new file to **exactly** match the original filename (e.g., \`SaveData0.dat\`)
6. Launch the game and load the save to verify your changes

> **Tip:** The filename must match exactly, including capitalization. If the original was \`SaveData0.dat\`, your new file must also be \`SaveData0.dat\`, not \`savedata0.dat\` or \`SaveData0_edited.dat\`.`
		},
		{
			id: "troubleshooting",
			title: "Troubleshooting & FAQ",
			content: `## "HMAC verification failed"

This means the Master Key doesn't match the one used to create the save file. Common causes:

- You copied the key incorrectly, try the PowerShell command again and paste carefully
- You're trying to decrypt a save file from a different PC, each PC has its own key
- The save file is corrupted

## "Invalid Master Key format"

The tool expects either:
- A **64-character hex string** (letters A-F and numbers 0-9 only)
- A **registry value string** (the raw Base64 value from the Windows Registry)

Make sure you didn't accidentally copy extra spaces or newline characters.

## "Invalid JSON file" when encrypting

Your edited JSON has a syntax error. Common mistakes:
- Missing or extra **commas**, there should be a comma after each value except the last one in a group
- Missing **quotes** around text values
- Deleted a **curly brace** \`{ }\` or **bracket** \`[ ]\`

> **Tip:** Paste your JSON into [jsonlint.com](https://jsonlint.com), it will tell you exactly which line has the error.

## The game ignores my edited save

- Make sure the game was **fully closed** before you replaced the file
- Check that the filename **exactly matches** the original (including capitalization)
- Verify the file is in the right folder: \`%UserProfile%\\AppData\\LocalLow\\Playmeow\\性轉契約與痴漢少女\`

## Can I transfer saves between PCs?

Not directly. Each PC has a different Master Key, so a save encrypted on one PC can't be decrypted on another. However, you can:

1. Decrypt the save on the **original PC** (download the JSON)
2. Copy the JSON to the **new PC**
3. Get the Master Key on the **new PC**
4. Encrypt the JSON using the new PC's key
5. Place the new \`.dat\` file in the save folder on the new PC

## I can't find any .dat files

- Make sure you've actually **saved your game** at least once (not just launched it)
- Enable **hidden files** in File Explorer: click **View** → check **Hidden items**
- Double-check you're looking in the right folder, paste the full path from Step 2 into the Run dialog`
		}
	];

	// --- State ---
	// Editable Advanced Parameters
	let aesInfoStr = $state(DEFAULT_AES_INFO);
	let hmacInfoStr = $state(DEFAULT_HMAC_INFO);
	let saltPrefix = $state(DEFAULT_SALT_PREFIX);

	let masterKeyInput = $state("");
	let isProcessing = $state(false);

	let decryptFile: File | null = $state(null);
	let encryptFile: File | null = $state(null);

	let decryptedJson = $state("");
	let jsonLines = $derived(decryptedJson ? decryptedJson.split("\n") : []);

	let downloadUrl = $state("");
	let downloadName = $state("");

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
			const keyBytes = normalizeMasterKey(masterKeyInput, saltPrefix);
			const fileBuffer = await decryptFile.arrayBuffer();
			const fileBytes = new Uint8Array(fileBuffer);

			const json = await decryptData(fileBytes, keyBytes, aesInfoStr, hmacInfoStr);

			const parsedJson = JSON.parse(json);
			decryptedJson = JSON.stringify(parsedJson, null, 2);

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
			const keyBytes = normalizeMasterKey(masterKeyInput, saltPrefix);
			const fileText = await encryptFile.text();

			try {
				JSON.parse(fileText);
			} catch {
				throw new Error("Invalid JSON file.");
			}

			const encryptedBytes = await encryptData(fileText, keyBytes, aesInfoStr, hmacInfoStr);
			toast.success("Encryption successful!");

			const blob = new Blob([encryptedBytes as BlobPart], { type: "application/octet-stream" });
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

<div class="relative container mx-auto max-w-3xl space-y-8 py-10">
	<div class="relative space-y-2 text-center">
		<h1 class="text-3xl font-bold tracking-tighter">Save File Tool</h1>
		<p class="text-muted-foreground">
			Decrypt and re-encrypt game saves for the game<br />"Sex Change Contract and Molester Girl"
			(性轉契約與痴漢少女), accurate as of version 1.4.3
		</p>

		<div class="absolute top-0 right-0">
			<Dialog.Root>
				<Dialog.Trigger>
					{#snippet child({ props })}
						<Button variant="outline" size="icon" {...props} class="rounded-full">
							<CircleQuestionMark class="h-5 w-5 text-muted-foreground" />
							<span class="sr-only">Step-by-Step Guide</span>
						</Button>
					{/snippet}
				</Dialog.Trigger>
				<Dialog.Content class="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
					<Dialog.Header>
						<Dialog.Title class="flex items-center gap-2">
							<BookOpen class="h-5 w-5" /> Step-by-Step Guide
						</Dialog.Title>
						<Dialog.Description>
							A complete walkthrough for editing your save file, from start to finish.
						</Dialog.Description>
					</Dialog.Header>
					<Accordion.Root type="single" class="w-full">
						{#each guideSections as section (section.id)}
							<Accordion.Item value={section.id}>
								<Accordion.Trigger>{section.title}</Accordion.Trigger>
								<Accordion.Content>
									<MarkdownContent source={section.content} />
								</Accordion.Content>
							</Accordion.Item>
						{/each}
					</Accordion.Root>
				</Dialog.Content>
			</Dialog.Root>
		</div>
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
					<Accordion.Trigger
						class="bg-muted p-2 text-sm font-medium text-muted-foreground hover:no-underline"
					>
						<div class="flex items-center gap-2">
							<Settings class="h-4 w-4" /> Additional Parameters
						</div>
					</Accordion.Trigger>
					<Accordion.Content class="space-y-4 pt-2 pb-0">
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
								<RotateCcw class="h-3 w-3" /> Reset Defaults
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
									{#snippet children(item: string)}
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
