<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import { ModeWatcher } from "mode-watcher";
	import { Toaster } from "@/components/ui/sonner";

	let { children } = $props();
</script>

<ModeWatcher defaultMode="system" />
<Toaster />

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Save File Tool | Sex Change Contract and Molester Girl (性轉契約與痴漢少女)</title>

	<meta
		name="description"
		content="A client-side tool to decrypt, edit, and re-encrypt game save files (.dat) for the game 'Sex Change Contract and Molester Girl'."
	/>
	<meta
		name="keywords"
		content="Save Editor, Sex Change Contract and Molester Girl, 性轉契約與痴漢少女, Playmeow, Decrypt .dat, Encrypt save, Game Tools"
	/>
	<meta name="author" content="Save File Tool" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />

	<meta property="og:type" content="website" />
	<meta property="og:title" content="Save File Tool | Sex Change Contract and Molester Girl" />
	<meta
		property="og:description"
		content="Decrypt and edit your .dat save files easily. Tested on version 1.4.3. Runs entirely in your browser."
	/>
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:title" content="Save File Tool | Sex Change Contract and Molester Girl" />
	<meta
		name="twitter:description"
		content="Decrypt and edit your .dat save files easily. Tested on version 1.4.3. Runs entirely in your browser."
	/>
</svelte:head>

<main class="p-4">
	{@render children()}
</main>
