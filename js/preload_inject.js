
// Same guard as preload.js: skip the initial about:blank and the chrome-error://
// fallback so stage 2 doesn't patch globals or set a hash on a throwaway page.
if (window.location.href === 'about:blank'
        || window.location.protocol === 'chrome-error:') {
    return;
}

// Augment rsjsstorage rather than replace it: preload.js (loaded at context
// level) sets up the hook pipeline (addSink, canary, etc.). Replacing the
// object here would leave those hooks calling undefined methods.
window.rsjsstorage = window.rsjsstorage || {};
Object.assign(window.rsjsstorage, {
    jsEvals: [],
    alertfunc: function (key) {
        if (this.jsEvals.indexOf(key) === -1) {
            this.jsEvals.push(key);
        }
    },

    // injected from python: {key: payload}
    payloadMap: "{{payload_map}}",
    hashPayload: "{{hash_payload}}",
});

// Mirror stage-1 delivery: preload.js pushStates the topparam canaries, so
// SPAs that gate rendering on real URL params (or parse location.search
// without URLSearchParams) entered the sink path in stage 1. Without this
// pushState, stage 2 reboots the page at a bare URL, the route never
// re-engages, USP hooks are never called, and no payload is delivered.
// The value is MINIMALLY percent-encoded (only % & # + space): quote
// characters stay raw so pages that read location.search RAW (regex, no
// decodeURIComponent) receive the payload's quotes unencoded and string
// breakouts work. Client-side only: no request leaves the page with these
// values. (Mirrors build_payload_url in mthook.py / mthook.js.)
try {
    const href = window.location.href;
    const hashIdx = href.indexOf('#');
    const noHash = hashIdx === -1 ? href : href.slice(0, hashIdx);
    const qIdx = noHash.indexOf('?');
    const before = qIdx === -1 ? noHash : noHash.slice(0, qIdx);
    const rawQuery = (qIdx === -1 || qIdx === noHash.length - 1) ? '' : noHash.slice(qIdx + 1);
    const parts = rawQuery === '' ? [] : rawQuery.split('&');
    const payloadMap = window.rsjsstorage.payloadMap;
    const keys = Object.keys(payloadMap);
    function enc(v) {
        return v.split('%').join('%25').split('&').join('%26')
            .split('#').join('%23').split('+').join('%2B').split(' ').join('%20');
    }
    function keyOf(p) {
        const eq = p.indexOf('=');
        return eq === -1 ? p : p.slice(0, eq);
    }
    const out = parts.map(function (p) {
        return keys.indexOf(keyOf(p)) !== -1 ? keyOf(p) + '=' + enc(payloadMap[keyOf(p)]) : p;
    });
    keys.forEach(function (k) {
        if (!parts.some(function (p) { return keyOf(p) === k; })) {
            out.push(k + '=' + enc(payloadMap[k]));
        }
    });
    const newUrl = before + '?' + out.join('&');
    if (newUrl !== noHash) {
        window.history.pushState(null, '', newUrl);
    }
} catch (e) {}

// hash injection (after pushState, so the payload fragment wins)
if (window.rsjsstorage.hashPayload) {
    window.location.hash = window.rsjsstorage.hashPayload;
}

//get
const originalGet = URLSearchParams.prototype.get;
URLSearchParams.prototype.get = function (key) {
    if (key in window.rsjsstorage.payloadMap) {
        return window.rsjsstorage.payloadMap[key];
    }
    // return originalGet.call(this, key);
    return "test";
};

//getAll
const originalGetAll = URLSearchParams.prototype.getAll;
URLSearchParams.prototype.getAll = function (key) {
    if (key in window.rsjsstorage.payloadMap) {
        return [window.rsjsstorage.payloadMap[key]];
    }
    return ['test'];
};

//has
const originalHas = URLSearchParams.prototype.has;
URLSearchParams.prototype.has = function (key) {
    return true;
};

// Fire event-handler sinks: pages like setAttribute('onclick', payload) run
// the handler only on user interaction, which stage 2 can't do per-element.
// After hydration, find elements whose on* attribute value carries one of
// our payloads (fingerprint: 'rsjsstorage') and dispatch the matching event
// ourselves. new Event() + dispatchEvent runs the handler WITHOUT default
// actions (no link navigation away from the page), unlike el.click().
(function () {
    var EVENTS = {
        click: ['click'], mouseover: ['mouseover'], mouseenter: ['mouseover'],
        mousedown: ['mousedown'], mouseup: ['mouseup'], focus: ['focus'],
        focusin: ['focus'], blur: ['focusout'], input: ['input'],
        change: ['change'], keydown: ['keydown'], keyup: ['keyup'],
        load: ['load'], error: ['error'], scroll: ['scroll'],
        submit: ['submit'], toggle: ['toggle'],
    };
    function fire() {
        try {
            var els = document.querySelectorAll('*');
            for (var i = 0; i < els.length; i++) {
                var el = els[i];
                for (var a = 0; a < el.attributes.length; a++) {
                    var attr = el.attributes[a];
                    var name = attr.name.toLowerCase();
                    if (name.lastIndexOf('on', 0) !== 0
                            || attr.value.indexOf('rsjsstorage') === -1) continue;
                    var evts = EVENTS[name.slice(2)];
                    if (!evts) continue;
                    for (var e = 0; e < evts.length; e++) {
                        try {
                            el.dispatchEvent(new Event(evts[e], { bubbles: true }));
                        } catch (err) {}
                    }
                }
            }
        } catch (e) {}
    }
    // Pages commonly assign the handler on their own load handler, so wait
    // for load + a hydration margin before firing (stage 2 waits 5s total).
    function schedule() { setTimeout(fire, 1500); }
    if (document.readyState === 'complete') schedule();
    else window.addEventListener('load', schedule);
})();
