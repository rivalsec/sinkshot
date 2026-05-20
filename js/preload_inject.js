
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

// hash injection
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
