```
╔══════════════════════════════════════════════════════╗
║  ▓█ ░▒▓█ D O M A I N S M I T H █▓▒░ █▓               ║
║ ┌─[~]─[192.168.x.x]───────────────────────────────┐  ║
║ │ > forging infrastructure . . . [ OK ]           │  ║
║ └──────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════╝
```

Tools for picking and setting up domains for authorized phishing-simulation
exercises. First, a two-step vetting pipeline checks whether a candidate
domain is available and whether it has a clean history. Second, a simple
placeholder page gives the registered domains something to serve.


---

## Workflow

```
names.txt ──> check-domains.sh ──> AVAILABLE names
                                        │
                                        ▼
                          domains.txt ──> burn-check.sh ──> CLEAN domains
                                                                │
                                                                ▼
                                            register ──> point at site/ page
```

1. **Availability** — `check-domains.sh` reads `names.txt` and reports which
   base names are unregistered across the TLDs you pass.
2. **Reputation / burn** — `burn-check.sh` reads `domains.txt` (full domains)
   and flags any that were previously registered and abused.
3. **Hosting** — `site/index.html` is the static placeholder page the
   registered domains point to.

---

## Files

```
rt-domains/
├── check-domains.sh     # Step 1: RDAP availability checker (no keys needed)
├── burn-check.sh        # Step 2: VirusTotal + urlscan reputation/burn checker
├── names.txt            # Input for step 1 — base names, one per line, no TLD
├── domains.txt          # Input for step 2 — full domains, one per line (name.tld)
├── .env                 # Your API keys for burn-check.sh (git-ignored, not committed)
├── .env.example         # Template to copy to .env
├── original_script.txt  # The original inline one-liner the checker grew from (scratch)
├── site/
│   └── index.html       # Static "under construction" placeholder page
└── README.md            # This file
```

### `check-domains.sh` — availability checker
Queries registry **RDAP** endpoints over HTTPS (no port-43 WHOIS, no scraping).
`404` = available, `200` = taken. No API keys required.

```bash
chmod +x check-domains.sh
./check-domains.sh names.txt              # defaults to .com/.net
./check-domains.sh names.txt com net org  # custom TLDs
```

Output: `AVAILABLE` (404, unregistered), `registered` (200, taken), or `? <code>`
for anything else (rate-limit, timeout — see tunables at the top of the script).

### `burn-check.sh` — reputation / burn checker
For each full domain, queries **VirusTotal** (detections, reputation, categories)
and **urlscan.io** (prior-scan history), then prints a `CLEAN` / `CAUTION` /
`DIRTY` verdict. Catches an available-but-previously-abused name that RDAP can't
see.

```bash
cp .env.example .env     # paste your keys in
chmod +x burn-check.sh
./burn-check.sh domains.txt
```

Needs a VirusTotal API key in `.env` (free tier works; the script paces calls
to stay under the rate limit). urlscan key is optional. A VT `404` ("no history")
is a good sign. Verdicts: `CLEAN` = no adverse history, `CAUTION` = manual review,
`DIRTY` = confirmed malicious history (avoid).

### `names.txt` / `domains.txt`
Two input files because the two scripts need different formats:
- **`names.txt`** — base names only (`benefitsenrollhub`); `check-domains.sh`
  appends the TLDs itself.
- **`domains.txt`** — full domains (`benefitsenrollhub.com`); reputation is
  per-exact-domain, so the TLD must be included.

Blank lines and lines starting with `#` are ignored in both.

### `.env` / `.env.example`
`.env.example` is the template; copy it to `.env` and paste your `VT_API_KEY`
(and optional `URLSCAN_API_KEY`). `.env` holds live secrets and is git-ignored —
never commit it.

### `site/index.html` — placeholder page
A self-contained static HTML page reading **"This site is under construction."**
Generic (no name-specific branding, so one page serves every domain), responsive,
light/dark aware, and set to `noindex, nofollow` so search engines don't catalog
it. Deployed to a static host (Netlify) and pointed to by the registered domains.
No JavaScript, no external dependencies — a single HTML file.

---

## Requirements

- `bash` and `curl` (standard on Linux / macOS / WSL) for both scripts.
- `jq` **or** `python3` for `burn-check.sh` JSON parsing (auto-detected).
- Outbound HTTPS to `rdap.verisign.com`, `rdap.org`, `rdap.publicinterestregistry.org`
  (for `.org`), `www.virustotal.com`, and `urlscan.io`.
- A VirusTotal API key for the burn check (see `.env.example`).

---

## Notes

- Run the scripts from **WSL/bash**, not PowerShell.
- If a script errors with `bad interpreter: ^M`, fix Windows line endings once:
  `sed -i 's/\r$//' check-domains.sh burn-check.sh`
- Availability can change between checking and registering — re-check right
  before you buy.

---
