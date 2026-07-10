# Cracka.dev — Suite Portal + License Admin

A mirror of the hub.cracka.gg neon site, retargeted for the developer/admin side:

| Tab       | Page          | What it does |
|-----------|---------------|--------------|
| Home      | `index.html`  | Hero + featured video window (random YouTube showcase, auto-swaps to the live Twitch player when @crackafpv is streaming) + portal cards |
| The Suite | `suite.html`  | The 7 suite tools (mirrored) |
| Content   | `content.html`| Featured video + latest YouTube grid + Twitch live override |
| 3D Print  | `prints.html` | MakerWorld models (mirrored) |
| About     | `about.html`  | Mirrored about page |
| License   | `license.html`| **License admin** — overview stats, search/filter, CSV export, and (with Discord login) issue / revoke / edit / resend |
| Contact   | `contact.html`| Contact form (relays via the Worker, or mailto fallback) |

Theme + images are pulled live from `https://hub.cracka.gg` (style.css + all art), so the two sites always match — nothing to copy.

## 1. Deploy the static site (GitHub Pages)
1. Create a repo, e.g. `Cracka813/cracka-dev`, and upload every `.html` file + `CNAME`.
2. Settings → Pages → Deploy from branch → `main` / root.
3. Porkbun DNS: `CNAME  cracka.dev → Cracka813.github.io` (or an ALIAS/ANAME on the root; add `www` CNAME too if you want it).
4. Wait for HTTPS to go green. Site is live at https://cracka.dev.

At this point Home, Suite, Content, 3D Print, About, Contact (mailto mode), and the **read-only** License overview all work with no backend.

## 2. Deploy the admin Worker (unlocks Discord login + editing)
Prereqs: the `wrangler` CLI and your Cloudflare account.
```
wrangler kv namespace create DASH_KV      # paste the id into wrangler.toml
wrangler secret put DISCORD_CLIENT_ID
wrangler secret put DISCORD_CLIENT_SECRET
wrangler secret put SESSION_SECRET        # any long random string
wrangler secret put GH_TOKEN              # GitHub token with contents:write on djcracka-suite
wrangler secret put CONTACT_WEBHOOK       # (optional) Make/Zoho webhook for contact + resend
wrangler deploy
```
Set `ADMIN_IDS` in `wrangler.toml` to your Discord user ID (right-click your name → Copy User ID with Developer Mode on). Only listed IDs can log in and edit.

### Discord app
In the Discord Developer Portal → your app → OAuth2:
- Add redirect: `https://cracka-dashboard.<your-subdomain>.workers.dev/auth/discord/callback`
- Scope used: `identify`

### Wire the pages to the Worker
In `license.html` and `contact.html`, set the `WORKER` constant near the bottom to your Worker URL, e.g.
```
var WORKER="https://cracka-dashboard.<your-subdomain>.workers.dev";
```
Re-upload those two files. Done — "Login with Discord" now works, edits write to `Cracka_Suite_License.json` (GitHub, mirrored to KV), and the contact form relays through the Worker.

## Data flow
- **Reads:** GitHub raw JSON first → Cloudflare KV fallback (source shown at the bottom of the table).
- **Writes:** Worker → GitHub Contents API (versioned commit) → KV mirror. Admin-gated by Discord login.
- **Contact / resend:** Worker → your Make/Zoho `CONTACT_WEBHOOK`.
