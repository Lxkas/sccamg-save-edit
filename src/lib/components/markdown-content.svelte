<script lang="ts">
	import { Lexer, type Token, type Tokens } from "marked";
	import { AlertTriangle, Lightbulb } from "@lucide/svelte";

	interface Props {
		source: string;
	}

	let { source }: Props = $props();

	let tokens = $derived(Lexer.lex(source));

	// detect callout type from blockquote text
	function getCalloutType(token: Tokens.Blockquote): "warning" | "tip" | null {
		const firstParagraph = token.tokens?.find((t): t is Tokens.Paragraph => t.type === "paragraph");
		if (!firstParagraph) return null;
		const firstChild = firstParagraph.tokens?.[0];
		if (firstChild?.type === "strong") {
			const text = firstChild.text.toLowerCase();
			if (text.startsWith("warning")) return "warning";
			if (text.startsWith("tip")) return "tip";
		}
		return null;
	}
</script>

{#snippet inlineTokens(items: Token[])}
	{#each items as token, i (i)}
		{#if token.type === "text"}
			{#if "tokens" in token && token.tokens}
				{@render inlineTokens(token.tokens)}
			{:else}
				{token.raw}
			{/if}
		{:else if token.type === "strong"}
			<strong class="font-semibold">{@render inlineTokens((token as Tokens.Strong).tokens)}</strong>
		{:else if token.type === "em"}
			<em>{@render inlineTokens((token as Tokens.Em).tokens)}</em>
		{:else if token.type === "codespan"}
			<code class="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{(token as Tokens.Codespan).text}</code>
		{:else if token.type === "link"}
			<!-- external links from markdown content, not internal routes -->
			<a
				href={(token as Tokens.Link).href}
				target="_blank"
				rel="noopener noreferrer"
				class="text-primary underline underline-offset-2 hover:text-primary/80"
			>
				{@render inlineTokens((token as Tokens.Link).tokens)}
			</a>
		{:else if token.type === "br"}
			<br />
		{:else}
			{token.raw}
		{/if}
	{/each}
{/snippet}

{#snippet blockTokens(items: Token[])}
	{#each items as token, i (i)}
		{#if token.type === "paragraph"}
			<p class="leading-relaxed [&:not(:last-child)]:mb-3">
				{@render inlineTokens((token as Tokens.Paragraph).tokens)}
			</p>
		{:else if token.type === "heading"}
			{@const level = (token as Tokens.Heading).depth}
			{#if level === 1}
				<h3 class="mt-4 mb-2 text-lg font-semibold first:mt-0">
					{@render inlineTokens((token as Tokens.Heading).tokens)}
				</h3>
			{:else if level === 2}
				<h4 class="mt-3 mb-2 text-base font-semibold first:mt-0">
					{@render inlineTokens((token as Tokens.Heading).tokens)}
				</h4>
			{:else}
				<h5 class="mt-2 mb-1 text-sm font-semibold first:mt-0">
					{@render inlineTokens((token as Tokens.Heading).tokens)}
				</h5>
			{/if}
		{:else if token.type === "list"}
			{@const list = token as Tokens.List}
			{#if list.ordered}
				<ol class="mb-3 list-decimal space-y-1 pl-6 text-sm">
					{#each list.items as item, j (j)}
						<li class="leading-relaxed">
							{@render inlineTokens(item.tokens)}
						</li>
					{/each}
				</ol>
			{:else}
				<ul class="mb-3 list-disc space-y-1 pl-6 text-sm">
					{#each list.items as item, j (j)}
						<li class="leading-relaxed">
							{@render inlineTokens(item.tokens)}
						</li>
					{/each}
				</ul>
			{/if}
		{:else if token.type === "code"}
			<pre class="mb-3 overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed"><code
					>{(token as Tokens.Code).text}</code
				></pre>
		{:else if token.type === "blockquote"}
			{@const callout = getCalloutType(token as Tokens.Blockquote)}
			{#if callout === "warning"}
				<div class="mb-3 flex gap-2 rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm">
					<AlertTriangle class="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
					<div class="min-w-0">{@render blockTokens((token as Tokens.Blockquote).tokens)}</div>
				</div>
			{:else if callout === "tip"}
				<div class="mb-3 flex gap-2 rounded-md border border-muted-foreground/30 bg-muted p-3 text-sm">
					<Lightbulb class="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
					<div class="min-w-0">{@render blockTokens((token as Tokens.Blockquote).tokens)}</div>
				</div>
			{:else}
				<blockquote class="mb-3 border-l-2 border-muted-foreground/30 pl-4 text-sm italic">
					{@render blockTokens((token as Tokens.Blockquote).tokens)}
				</blockquote>
			{/if}
		{:else if token.type === "space"}
			<!-- spacing token, no output -->
		{:else if token.type === "hr"}
			<hr class="my-4 border-muted-foreground/20" />
		{:else}
			{token.raw}
		{/if}
	{/each}
{/snippet}

<div class="text-sm text-foreground">
	{@render blockTokens(tokens)}
</div>
