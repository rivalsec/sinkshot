# SinkShot

DOM XSS scanner built on Playwright. For each input URL, every query value is replaced with a marker (`<canary><param>`), a preload script hooks DOM reads and dangerous sinks, and any sink whose value still contains the marker is flagged as a flow from that param. Confirmed flows are then re-driven with context-aware payloads, and execution is verified by an `alertfunc` callback firing inside the page.

## How it works

**Stage 1 — discovery.** [js/preload.js](js/preload.js) is added via Playwright's `addInitScript`, so it runs before any page script:
- Rewrites the URL so every existing query value becomes `<canary><key>`, then `pushState`s the same canary into a curated `topparams` list from [config.yaml](config.yaml) (so the page sees common names like `redirect`/`url`/`q` even when they weren't in the URL). The fragment is set to `#<canary>_hash`.
- Hooks `URLSearchParams.get/getAll/has` so even keys the page asks for but the URL doesn't contain still return a canary value, and records every key read into `uspRevealed`.
- Hooks JS sinks (`eval`, `Function`, string `setTimeout`/`setInterval`, `script.text`/`textContent`), HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write[ln]`), DOM URL sinks (`a.href`, `form.action`, `*.src`), and generic `setAttribute` (recorded as `setAttribute_<tag>_<attr>`). Any sunk string containing the canary is recorded with the matched source keys and a snippet of the offending code.
- `Location.{assign,replace,href}` cannot be patched reliably in Chromium (own non-configurable props), so navigation-based sinks are instead caught at the network layer: a Playwright route handler watches main-frame requests and records any post-load navigation whose URL contains the canary as `location_nav`, then fulfills it with HTTP 204 to keep the page (and `rsjsstorage`) alive.
- The Python side ([mthook.py](mthook.py)) also captures the main document's raw HTML response and scans it with `lxml` for reflected canaries, tagging hits by context (html / script / style / attr).

**Stage 2 — confirmation.** For each new sink, [`get_payloads`](mthook.py#L242) builds a context-appropriate payload — quote-count-based string-literal break-out for JS sinks, `javascript:rsjsstorage.alertfunc(...)` for URL/href-style sinks, a tag-break payload that closes `style`/`title`/`textarea`/`script` and uses `<img onerror>` for HTML sinks. The page is reloaded with [js/preload_inject.js](js/preload_inject.js), which makes `URLSearchParams.get(key)` return the payload for that key and pushes the hash payload into `location.hash`. A flow is confirmed when the payload's `rsjsstorage.alertfunc(key)` actually runs and `key` ends up in `window.rsjsstorage.jsEvals`. For URL sinks where the canary controls the full URL or its netloc (which can't be auto-triggered because there's no real click), confirmation is decided statically by `static_confirm_url_sinks` without needing stage 2 to fire.

Per-domain dedup (`-D`, optional) hashes `sink|sources|code` and `keys|context|tag|attr` so the same finding on a different URL of the same host isn't reprinted. A per-domain error counter (`DOMAIN_MAX_ERRORS = 10`) silently skips hosts that keep failing. A watchdog ticks every 5s and kills any worker whose browser has been busy on the same URL for more than `WORKER_TIMEOUT` (60s), respawning a replacement; workers also recycle their browser every `BROWSER_REFRESH_INTERVAL` (20) URLs to cap memory growth.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

From a file:
```bash
python mthook.py -u urls.txt -t 10
```

From stdin:
```bash
cat urls.txt | python mthook.py -t 10
```

Flags:
- `-u, --urls FILE` — newline-separated URLs (omit to read stdin).
- `-t, --threads N` — number of parallel browser workers (default `10`).
- `-w, --wait SECONDS` — extra `networkidle` wait after stage-1 load (default `0`).
- `-o, --output FILE` — append confirmed findings to file (truncated on open).
- `-d, --debug` — print unconfirmed sinks and reflected hits to stderr.
- `-D, --dedup` — enable per-domain sink/reflected deduplication.

## Docker

Build the image:
```bash
docker build -t sinkshot .
```

Run against a URL file on the host (mount it in and reference the container path):
```bash
docker run --rm -v "$PWD/urls.txt:/urls.txt:ro" sinkshot -u /urls.txt -t 10
```

From stdin:
```bash
cat urls.txt | docker run --rm -i sinkshot -t 10
```

## Config

[config.yaml](config.yaml):
- `canary` — marker string injected into params (e.g. `rivalsss`). Pick something unlikely to collide with site content.
- `preload_script` — path to the stage-1 hook script (default `js/preload.js`).
- `ua` — user agent used by all pages.
- `topparams` — extra param names auto-injected via `pushState` so sites that read e.g. `?redirect=...` without it being in the URL still get probed.

## Output

For each URL with findings, a dict is printed with:
- `originurl` — URL captured at hook init.
- `dom_url` — original URL plus any `uspRevealed` keys appended as `key=<canary>key`, useful for re-running with all read keys present.
- `uspRevealed` — param keys the page actually read.
- `sinks` — new sink entries `{sink, sources, code}`.
- `confirmed` — payloads from stage 2 whose `alertfunc` actually fired.
- `reflected` — server-side reflections found in the raw HTML.

`stderr` carries per-domain error counts and watchdog kills.

## Layout

- [mthook.py](mthook.py) — orchestrator: queue, workers, watchdog, stage 1/2 logic, dedup.
- [js/preload.js](js/preload.js) — stage-1 hooks (`{{canary}}` and `{{topparams}}` are templated in).
- [js/preload_inject.js](js/preload_inject.js) — stage-2 hooks with `payload_map` substitution.
- [config.yaml](config.yaml) — canary, UA, top params, preload path.

## Test lab

A companion Flask app with DOM XSS test cases lives at https://github.com/rivalsec/domxsslab — useful for exercising the scanner end-to-end.

## Reference

- Playwright (Python): https://playwright.dev/python/docs/library
