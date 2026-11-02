
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
// Values are percent-encoded by searchParams — same as stage 1; pages that
// decodeURIComponent (or use USP) get the raw payload. Client-side only:
// no request leaves the page with these values.
try {
    const injectUrl = new URL(window.location.href);
    Object.keys(window.rsjsstorage.payloadMap).forEach(function (key) {
        injectUrl.searchParams.set(key, window.rsjsstorage.payloadMap[key]);
    });
    if (injectUrl.toString() !== window.location.href) {
        window.history.pushState(null, '', injectUrl.toString());
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
