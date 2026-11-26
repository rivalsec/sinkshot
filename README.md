# SinkShot

DOM XSS scanner built on Playwright. For each input URL, every query value is replaced with a marker (`<canary><param>`), a preload script hooks DOM reads and dangerous sinks, and any sink whose value still contains the marker is flagged as a flow from that param. Confirmed flows are then re-driven with context-aware payloads, and execution is verified by an `alertfunc` callback firing inside the page.

There are two interchangeable implementations with the same behavior and CLI flags: [mthook.py](mthook.py) (Python) and [mthook.js](mthook.js) (Node.js). The stage-1/stage-2 hook scripts in [js/](js/) are shared by both.

## How it works

**Stage 1 — discovery.** [js/preload.js](js/preload.js) is added via Playwright's `addInitScript`, so it runs before any page script:
- Rewrites the URL so every existing query value becomes `<canary><key>`, then `pushState`s the same canary into a curated `topparams` list from [config.yaml](config.yaml) (so the page sees common names like `redirect`/`url`/`q` even when they weren't in the URL). The fragment is set to `#<canary>_hash`.
- Hooks `URLSearchParams.get/getAll/has` so even keys the page asks for but the URL doesn't contain still return a canary value, and records every key read into `uspRevealed`.
- Hooks JS sinks (`eval`, `Function`, string `setTimeout`/`setInterval`, `script.text`/`textContent`), HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write[ln]`), DOM URL sinks (`a.href`, `form.action`, `*.src`), and generic `setAttribute` (recorded as `setAttribute_<tag>_<attr>`). Any sunk string containing the canary is recorded with the matched source keys and a snippet of the offending code. URL-attribute writes additionally record the element itself (`window.__rsUrlSinkEls`) so stage 2 can later check whether that element is still connected and still carries the payload.
- `Location.{assign,replace,href}` cannot be patched reliably in Chromium (own non-configurable props), so navigation-based sinks are instead caught at the network layer: a Playwright route handler watches main-frame requests and records any post-load navigation whose URL contains the canary as `location_nav`, then fulfills it with HTTP 204 to keep the page (and `rsjsstorage`) alive.
- The orchestrator also captures the main document's raw HTML response and scans it for reflected canaries ([mthook.py](mthook.py) with `lxml`, [mthook.js](mthook.js) with `parse5`), tagging hits by context (html / script / style / attr).

**Stage 2 — confirmation.** For each new sink, [`get_payloads`](mthook.py#L615) builds a context-appropriate payload — quote-count-based string-literal break-out for JS sinks, `javascript:rsjsstorage.alertfunc(...)` for URL/href-style sinks, a tag-break payload that closes `style`/`title`/`textarea`/`script` and uses `<img onerror>` for HTML sinks. The page is reloaded with [js/preload_inject.js](js/preload_inject.js), which makes `URLSearchParams.get(key)` return the payload for that key and pushes the hash payload into `location.hash`. A flow is confirmed when the payload's `rsjsstorage.alertfunc(key)` actually runs and `key` ends up in `window.rsjsstorage.jsEvals`. URL sinks can't be auto-clicked, so they confirm in two ways: navigation sinks (`location_*`, `window_open`) statically, when the canary controls the whole URL value — they act by themselves; and element URL sinks (`a.href`, `*.src`, `form.action`, URL-valued `setAttribute`) only when the delivered payload still sits at the start of a URL attribute of an element **connected in the settled DOM** ([`confirm_url_sinks`](mthook.py#L579) + `DOM_PRESENT_JS`, findings marked `via=dom`). That DOM-presence requirement is what keeps throwaway elements out of the report: the detached `<a>` many sites create purely to parse a URL, elements whose attributes are set before an async step that fails (so they are never appended), and values the page drops or rewrites once they stop looking like benign input all stay unconfirmed.

Per-domain dedup (`-D`, optional) hashes `sink|sources|code` and `keys|context|tag|attr` so the same finding on a different URL of the same host isn't reprinted. A per-domain error counter (`DOMAIN_MAX_ERRORS = 10`) silently skips hosts that keep failing. A watchdog ticks every 5s and kills any worker whose browser has been busy on the same URL for more than `WORKER_TIMEOUT` (60s), respawning a replacement; workers also recycle their browser every `BROWSER_REFRESH_INTERVAL` (50) URLs to cap memory growth.

## Install

Python:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

Node.js:
```bash
npm install
npx playwright install chromium
```

## Usage

Python:
```bash
python mthook.py -u urls.txt -t 10
```

Node.js:
```bash
node mthook.js -u urls.txt -t 10
```

Both read from stdin when `-u` is omitted (the Node version exits with usage if stdin is a terminal instead of hanging):
```bash
cat urls.txt | python mthook.py -t 10
cat urls.txt | node mthook.js -t 10
```

Flags (identical in both implementations):
- `-u, --urls FILE` — newline-separated URLs (omit to read stdin).
- `-t, --threads N` — number of parallel browser workers (default `10`).
- `-w, --wait SECONDS` — networkidle settle window in seconds, stage 1 and stage-2 verification (default: 3s built in; raise for slow SPA/ad hydration).
- `-o, --output FILE` — append confirmed findings to file (truncated on open).
- `-d, --debug` — print unconfirmed sinks and reflected hits to stderr.
- `-D, --dedup` — enable per-domain sink/reflected deduplication.
- `-c, --crawl DEPTH` — crawl mode: harvest same-host links from every scanned page and scan them breadth-first up to DEPTH levels deep (default off). Each depth level's links are shuffled, so `--max-urls` trims a random sample of the deepest level rather than a fixed DOM-order prefix.
- `--max-urls N` — cap on total URLs scanned when crawling (default `500`; seeds are always scanned).
- `-H, --header "Name: Value"` — extra HTTP header sent on every request (repeatable).
- `--ua UA` — override the User-Agent from [config.yaml](config.yaml).
- `--headed` — run browsers visibly (needs a display).
- `--viewport WxH` — fixed viewport size, e.g. `430x932` (default `1280x720`).
- `--session PATH` — load a Playwright storage_state JSON (cookies + localStorage) into every context and keep cookies across URLs.
- `--capture-session URL` — headed one-off: open `URL` visibly, let you pass a WAF/captcha, save cookies to the path given in `--session`.

## Sessions for WAF-protected targets

Targets behind anti-bot WAFs usually clear the headless default. Capture a real session once, then reuse it for the scan — with the **same** `--ua` (and `--viewport`) on both steps, since WAF cookies are commonly bound to the User-Agent:

```bash
node mthook.js --capture-session https://target.example/ --session state.json --ua "Mozilla/5.0 ..."
node mthook.js -u urls.txt --session state.json --ua "Mozilla/5.0 ..." -t 10
```

## Docker

Python version — build and run:
```bash
docker build -t sinkshot .
docker run --rm -v "$PWD/urls.txt:/urls.txt:ro" sinkshot -u /urls.txt -t 10
# or: cat urls.txt | docker run --rm -i sinkshot -t 10
```

Node.js version — build with [Dockerfile.node](Dockerfile.node):
```bash
docker build -f Dockerfile.node -t sinkshot-node .
docker run --rm -v "$PWD/urls.txt:/urls.txt:ro" sinkshot-node -u /urls.txt -t 10
# or: cat urls.txt | docker run --rm -i sinkshot-node -t 10
```

The Node image is based on `mcr.microsoft.com/playwright` and ships Chromium + system deps preinstalled (no `playwright install` needed). Its image tag **must** match the playwright version resolved in [package-lock.json](package-lock.json) — a mismatch fails at launch with `Executable doesn't exist`.

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

Confirmed PoC lines in the output file look like `<poc-url>  [sink=a_href ctx=url]`, with an extra `via=dom` marker when the finding was confirmed by DOM presence (payload rendered on a connected element's URL attribute) rather than by execution — those need a manual click on the rendered link to fire.

`stderr` carries per-domain error counts and watchdog kills.

## Layout

- [mthook.py](mthook.py) — Python orchestrator: queue, workers, watchdog, stage 1/2 logic, dedup.
- [mthook.js](mthook.js) — Node.js port of the orchestrator, same flags and behavior.
- [js/preload.js](js/preload.js) — stage-1 hooks (`{{canary}}` and `{{topparams}}` are templated in).
- [js/preload_inject.js](js/preload_inject.js) — stage-2 hooks with `payload_map` substitution.
- [config.yaml](config.yaml) — canary, UA, top params, preload path.
- [Dockerfile](Dockerfile) / [Dockerfile.node](Dockerfile.node) — Python and Node.js container images.
- [package.json](package.json) / [requirements.txt](requirements.txt) — Node and Python dependencies.

## Test lab

A companion Flask app with DOM XSS test cases lives at https://github.com/rivalsec/domxsslab — useful for exercising the scanner end-to-end.

## Reference

- Playwright (Python): https://playwright.dev/python/docs/library
