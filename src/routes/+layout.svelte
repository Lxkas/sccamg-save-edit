<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import { ModeWatcher } from "mode-watcher";
	import { Toaster } from "@/components/ui/sonner";

	let { children } = $props();
</script>

<ModeWatcher defaultMode="system" />
<Toaster />

<svelte:head><link rel="icon" href={favicon} /></svelte:head>

<main class="p-4">
	{@render children()}
</main>
