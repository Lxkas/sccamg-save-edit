# CLAUDE.md — sccamg-editor

## Development Commands

- `bun dev` — start dev server
- `bun run build` — production build
- `bun run preview` — preview production build
- `bun run check` — typecheck with svelte-check
- `bun run format` — format with Prettier
- `bun run lint` — check formatting

## Architecture

SvelteKit single-page app for decrypting, editing, and re-encrypting game save files. Crypto operations use AES-128-CBC encryption, HMAC-SHA256 authentication, and HKDF key derivation — all client-side via the Web Crypto API.

### Key Files

- `src/routes/+page.svelte` — main app logic (file upload, decryption, editing, encryption)
- `src/routes/+layout.svelte` — root layout with theme provider and toaster
- `src/lib/components/ui/` — shadcn-svelte components (accordion, alert, button, card, dialog, input, label, separator, sonner, tabs, textarea)
- `src/lib/utils.ts` — `cn()` utility (clsx + tailwind-merge)
- `src/lib/hooks/` — custom hooks
- `src/lib/assets/` — static assets

### UI Stack

- **bits-ui** — headless component primitives (shadcn-svelte foundation)
- **tailwind-variants** — variant-based styling
- **tailwind-merge** — class deduplication
- **@lucide/svelte** — icons
- **svelte-sonner** — toast notifications
- **mode-watcher** — dark/light theme
- **virtua** — virtual scrolling
- **marked** — markdown rendering

### Import Alias

`@/*` maps to `./src/lib/*` (configured in svelte.config.js)

### Deployment

Deployed on Vercel via `@sveltejs/adapter-auto`.

## Code Style

Prettier config (`.prettierrc`):
- Tabs, 4-wide
- Double quotes, semicolons
- No trailing commas
- 120 char print width
- Plugins: prettier-plugin-svelte, prettier-plugin-tailwindcss

## Svelte MCP Server

You are able to use the Svelte MCP server, where you have access to comprehensive Svelte 5 and SvelteKit documentation. Here's how to use the available tools effectively:

### Available MCP Tools:

#### 1. list-sections

Use this FIRST to discover all available documentation sections. Returns a structured list with titles, use_cases, and paths.
When asked about Svelte or SvelteKit topics, ALWAYS use this tool at the start of the chat to find relevant sections.

#### 2. get-documentation

Retrieves full documentation content for specific sections. Accepts single or multiple sections.
After calling the list-sections tool, you MUST analyze the returned documentation sections (especially the use_cases field) and then use the get-documentation tool to fetch ALL documentation sections that are relevant for the user's task.

#### 3. svelte-autofixer

Analyzes Svelte code and returns issues and suggestions.
You MUST use this tool whenever writing Svelte code before sending it to the user. Keep calling it until no issues or suggestions are returned.

#### 4. playground-link

Generates a Svelte Playground link with the provided code.
After completing the code, ask the user if they want a playground link. Only call this tool after user confirmation and NEVER if code was written to files in their project.
