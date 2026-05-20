
window.rsjsstorage = {
    originurl: window.location.href,
    uspRevealed: [],
    sinks: [],
    // jsAlerts: {},
    // htmlInserts: [],
    jsEvals: [],
    // funcArgs: [],

    alertfunc: function (msg) {
        this.jsEvals.push(msg)
    },

    uspAddKey: function (key) {
        if (this.uspRevealed.indexOf(key) == -1) {
            this.uspRevealed.push(key)
        }
    },

    addSink: function (text, stype) {
        let rgxp = new RegExp(this.canary + "[a-zA-Z0-9_.\\[\\]\\-]+", "g")
        let matches = text.match(rgxp)
        if (!matches || !matches.length) return;
        let sources = [...new Set(matches.map(m => m.substring(this.canary.length)))];
        let entry = {sources: sources, sink: stype, code: text};
        let entryStr = JSON.stringify(entry);
        if (this.sinks.some(s => JSON.stringify(s) === entryStr)) return;
        this.sinks.push(entry);
    },
};

const rscanary = "{{canary}}";
window.rsjsstorage.canary = rscanary

// See rsCanaryValue() below — same wrapping for canary values written into the
// URL by pushState, so a later USP.get() pass-through stays bracketed.
function rsCanaryValue(key) { return "<" + rscanary + key + ">"; }

//add params without reload
const url = new URL(window.location.href);
rstopparams = "{{topparams}}";
rstopparams.forEach((p) => {
    if (!url.searchParams.has(p)) {
        url.searchParams.set(p, rsCanaryValue(p));
    }
});
window.history.pushState(null, '', url.toString());


// Wrap the synthetic canary in `<...>` (rsCanaryValue, defined above) so callers
// that gate on an HTML-looking shape (jQuery's buildFragment regex, `$(input)`
// selector-vs-HTML check, etc.) route the value through their HTML-parse path —
// which is where our innerHTML hook actually fires. Harmless for other sinks:
// addSink's regex still matches the canary substring inside the wrapped value;
// quote-count context detection ignores `<`/`>`; URL sinks still see the
// canary in the resolved request URL.

//get
const originalGet = URLSearchParams.prototype.get;
URLSearchParams.prototype.get = function (key) {
    window.rsjsstorage.uspAddKey(key);
    const val = originalGet.call(this, key);
    if (val && val.includes(rscanary)) return val;
    return rsCanaryValue(key);
};

//getAll
const originalGetAll = URLSearchParams.prototype.getAll;
URLSearchParams.prototype.getAll = function (key) {
    window.rsjsstorage.uspAddKey(key);
    const vals = originalGetAll.call(this, key);
    if (vals.length && vals.some(v => v.includes(rscanary))) return vals;
    return [rsCanaryValue(key)];
};

//has
const originalHas = URLSearchParams.prototype.has;
URLSearchParams.prototype.has = function (key) {
    window.rsjsstorage.uspAddKey(key);
    //return originalHas.call(this, key); // Call the original method
    return true;
};


const originalEval = window.eval;

window.eval = function (code) {
    window.rsjsstorage.addSink(code, "eval")
    return originalEval.call(window, code);
};

// Also override Function constructor
const OrigFunction = window.Function;
window.Function = function (...args) {
    args.forEach(code => {
        window.rsjsstorage.addSink(code, "func")
    });
    // window.rsjsstorage.funcArgs.push(args)
    return new OrigFunction(...args);
};
window.Function.prototype = OrigFunction.prototype;

// setTimeout
const originalSetTimeout = window.setTimeout;
window.setTimeout = function (fn, delay, ...args) {
    if (typeof fn === 'string') {
        window.rsjsstorage.addSink(fn, "setTimeout")
    }
    return originalSetTimeout.call(window, fn, delay, ...args);
};

// setInterval
const originalSetInterval = window.setInterval;
window.setInterval = function (fn, delay, ...args) {
    if (typeof fn === 'string') {
        window.rsjsstorage.addSink(fn, "setInterval")
    }
    return originalSetInterval.call(window, fn, delay, ...args);
};


// NOTE: in Chromium, Location.{assign,replace,href} are own non-configurable
// props on the location instance, not on Location.prototype. Prototype-level
// hooks here do not fire on `location.assign(...)` / `location.href = ...`.
// Navigation-style URL sinks are caught at the Playwright network layer in
// mthook.py (route handler fulfills main-frame canary navs with HTTP 204).
// These prototype overrides are kept only as a safety net for engines where
// prototype dispatch actually applies.
const originalAssign = Location.prototype.assign;
Location.prototype.assign = function (url) {
    const s = String(url);
    window.rsjsstorage.addSink(s, "location_assign")
    if (s.includes(rscanary)) return;
    return originalAssign.call(this, url);
};

const originalReplace = Location.prototype.replace;
Location.prototype.replace = function (url) {
    const s = String(url);
    window.rsjsstorage.addSink(s, "location_replace")
    if (s.includes(rscanary)) return;
    return originalReplace.call(this, url);
};

const locationHrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
if (locationHrefDesc) {
    Object.defineProperty(Location.prototype, 'href', {
        set(value) {
            const s = String(value);
            window.rsjsstorage.addSink(s, "location_href")
            if (s.includes(rscanary)) return;
            locationHrefDesc.set.call(this, value);
        },
        get() {
            return locationHrefDesc.get.call(this);
        }
    });
}

// window.open
const originalWindowOpen = window.open;
window.open = function (url, ...rest) {
    if (url !== undefined) {
        const s = String(url);
        window.rsjsstorage.addSink(s, "window_open")
        if (s.includes(rscanary)) return null;
    }
    return originalWindowOpen.call(this, url, ...rest);
};

// form.action
const actionDesc = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'action');
Object.defineProperty(HTMLFormElement.prototype, 'action', {
    set(value) {
        window.rsjsstorage.addSink(String(value), "form_action")
        actionDesc.set.call(this, value);
    },
    get() {
        return actionDesc.get.call(this);
    }
});

function htmlSinkType(el) {
    return (el && el.tagName === 'SCRIPT') ? "script_text" : "html";
}

// outerHTML
const outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
Object.defineProperty(Element.prototype, 'outerHTML', {
    set(value) {
        window.rsjsstorage.addSink(value, htmlSinkType(this))
        outerDesc.set.call(this, value);
    },
    get() {
        return outerDesc.get.call(this);
    }
});

// innerHTML
const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
    set(value) {
        window.rsjsstorage.addSink(value, htmlSinkType(this))
        innerDesc.set.call(this, value);
    },
    get() {
        return innerDesc.get.call(this);
    }
});

// insertAdjacentHTML
const originalInsert = Element.prototype.insertAdjacentHTML;
Element.prototype.insertAdjacentHTML = function (position, html) {
    window.rsjsstorage.addSink(html, htmlSinkType(this))
    originalInsert.call(this, position, html);
};

// Range.createContextualFragment
const originalCreateFragment = Range.prototype.createContextualFragment;
Range.prototype.createContextualFragment = function (html) {
    window.rsjsstorage.addSink(String(html), "html");
    return originalCreateFragment.call(this, html);
};

// DOMParser.parseFromString — inert until adopted, but XSS-equivalent in practice
const originalParseFromString = DOMParser.prototype.parseFromString;
DOMParser.prototype.parseFromString = function (str, type) {
    if (type === 'text/html') {
        window.rsjsstorage.addSink(String(str), "html");
    }
    return originalParseFromString.call(this, str, type);
};

// document.createElement — jQuery's parseHTML single-tag fast path
// (`$('<rivalsssinput>')`) calls createElement(tagName) directly, bypassing
// innerHTML. Record the canary tag as an HTML sink.
const originalCreateElement = document.createElement.bind(document);
document.createElement = function (name, options) {
    const s = String(name);
    if (s.includes(rscanary)) {
        window.rsjsstorage.addSink("<" + s + ">", "html");
    }
    return originalCreateElement(name, options);
};

// document.write
const originalWrite = document.write.bind(document);
document.write = function (html) {
    window.rsjsstorage.addSink(html, "html")
    originalWrite(html);
};

// document.writeln
const originalWriteln = document.writeln.bind(document);
document.writeln = function (html) {
    window.rsjsstorage.addSink(html, "html")
    originalWriteln(html);
};

// script.text / script.textContent
const scriptTextDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'text') ||
    Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
Object.defineProperty(HTMLScriptElement.prototype, 'text', {
    set(value) {
        window.rsjsstorage.addSink(value, "script_text")
        scriptTextDesc.set.call(this, value);
    },
    get() {
        return scriptTextDesc.get.call(this);
    }
});

// setAttribute
const originalSetAttribute = Element.prototype.setAttribute;
Element.prototype.setAttribute = function (name, value) {
    window.rsjsstorage.addSink(String(value), "setAttribute_" + (this.tagName || "").toLowerCase() + "_" + name);
    originalSetAttribute.call(this, name, value);
};

// src
const srcElements = [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement, HTMLSourceElement, HTMLEmbedElement];
srcElements.forEach(Ctor => {
    const srcDesc = Object.getOwnPropertyDescriptor(Ctor.prototype, 'src');
    if (!srcDesc) return;
    const tag = Ctor.prototype.constructor.name.replace('HTML', '').replace('Element', '').toLowerCase();
    Object.defineProperty(Ctor.prototype, 'src', {
        set(value) {
            window.rsjsstorage.addSink(String(value), tag + "_src")
            srcDesc.set.call(this, value);
        },
        get() {
            return srcDesc.get.call(this);
        }
    });
});

// href
const hrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
    set(value) {
        window.rsjsstorage.addSink(String(value), "a_href")
        hrefDesc.set.call(this, value);
    },
    get() {
        return hrefDesc.get.call(this);
    }
});

const scriptTextContentDesc = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');
Object.defineProperty(HTMLScriptElement.prototype, 'textContent', {
    set(value) {
        window.rsjsstorage.addSink(value, "script_text")
        scriptTextContentDesc.set.call(this, value);
    },
    get() {
        return scriptTextContentDesc.get.call(this);
    }
});
