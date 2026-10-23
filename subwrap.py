#!/usr/bin/env python3
"""
Generic local reverse proxy (subdomain-encoded target) -- SW tier.

    http://<host>.<port>.<scheme>.<BASE>/<path>   ->   <scheme>://<host>:<port>/<path>

With BASE = rp.localhost (default):
    http://example.com.443.https.rp.localhost/   -> https://example.com/
    http://a.com.8080.https.rp.localhost/x       -> https://a.com:8080/x
    http://a.com.rp.localhost/                   -> https://a.com/     (shorthand: 443/https)
    http://<alias>.rp.localhost/                 -> the target named by <alias> in config

Whole-site + cross-site + SPA:
  * target host lives in the Host header, so relative / root-relative URLs work untouched;
  * absolute URLs to *other* hosts (links, assets, redirects) are rewritten to their own
    encoded subdomain, so cross-site navigation stays inside the proxy;
  * a small JS shim is injected into every HTML page to catch RUNTIME urls that static
    rewriting can't see: fetch / XHR / sendBeacon / WebSocket / history / window.open /
    location.assign|replace / dynamic element src|href|action / anchor & form navigation;
  * WebSocket connections are tunnelled through (needed so the shim's ws rewrites work).

Configuration lives in subwrap.ini (base domain, listen port, bind address, aliases) --
nothing site-specific is baked into this file. See subwrap.example.ini.

Usage:
    python subwrap.py                 # read ./subwrap.ini (or built-in defaults)
    python subwrap.py /path/to.ini    # read a specific config file
"""

import os
import re
import sys
import ssl
import gzip
import zlib
import errno
import socket
import select
import threading
import configparser
import http.server
import http.client
from urllib.parse import urlsplit

# ---------------------------------------------------------------- config ----
DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Built-in defaults. Everything deployment- or site-specific lives in the config
# file (subwrap.ini), NOT here -- so the source tree ships with none of it.
_DEFAULTS = {"base": "rp.localhost", "port": 80, "bind": "loopback"}


def _bind_addresses(value):
    v = (value or "loopback").strip().lower()
    if v in ("loopback", "local", "localhost"):
        return ["127.0.0.1", "::1"]
    if v in ("all", "lan", "any"):
        return ["0.0.0.0", "::"]                        # reachable from the network
    return [a.strip() for a in v.split(",") if a.strip()]


def load_config():
    """Read subwrap.ini (path from argv[1], else next to this script). Everything
    optional; missing file -> built-in defaults, so the tool runs out of the box."""
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "subwrap.ini")
    base, port, bind, aliases = _DEFAULTS["base"], _DEFAULTS["port"], _DEFAULTS["bind"], {}
    if os.path.exists(path):
        cp = configparser.ConfigParser(interpolation=None)
        cp.optionxform = str                            # keep option names as written
        cp.read(path, encoding="utf-8")
        base = cp.get("server", "base", fallback=base).strip()
        port = cp.getint("server", "port", fallback=port)
        bind = cp.get("server", "bind", fallback=bind)
        if cp.has_section("aliases"):
            for label, url in cp.items("aliases"):
                u = urlsplit(url if "://" in url else "https://" + url)
                scheme = (u.scheme or "https").lower()
                if u.hostname:
                    aliases[label.strip().lower()] = (
                        scheme, u.hostname.lower(),
                        u.port or DEFAULT_PORT.get(scheme, 443))
    else:
        sys.stderr.write(f"  (no config at {path}; using built-in defaults)\n")
    return {"base": base, "port": port, "bind": _bind_addresses(bind),
            "config_path": path, "aliases": aliases}


_CFG = load_config()
BASE = _CFG["base"]                                     # e.g. rp.localhost (SW needs .localhost)
LISTEN_PORT = _CFG["port"]
PORT_SUFFIX = "" if LISTEN_PORT == 80 else f":{LISTEN_PORT}"
BIND_ADDRS = _CFG["bind"]
# Short-domain aliases: <label> -> (scheme, host, port), from the [aliases] config.
#   http://b.rp.localhost/  ==  http://example.com.443.https.rp.localhost/
# The alias is what shows in the browser: every place the long encoded host would be
# emitted (body/header rewrites, redirects, client shim, service worker), the alias is
# emitted instead, and a long-form navigation is redirected to the short form.
ALIASES = _CFG["aliases"]
ALIAS_REV = {v: k for k, v in ALIASES.items()}         # (scheme, host, port) -> label

SSL_CTX = ssl._create_unverified_context()              # local testing: skip backend verify

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
DROP_RESP = HOP | {
    "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "public-key-pins",
    "public-key-pins-report-only", "expect-ct", "alt-svc",
}
TEXT_HINTS = ("text/", "javascript", "json", "xml", "html", "css", "svg", "ecmascript")

URL_RE_B = re.compile(rb'(https?)://([A-Za-z0-9.\-]+)(?::(\d+))?')
URL_RE_S = re.compile(r'(https?)://([A-Za-z0-9.\-]+)(?::(\d+))?')


# ------------------------------------------------------------- encode/decode ----
def alias_for(scheme, host, port):
    return ALIAS_REV.get((scheme, host.lower(), port))


def encode(scheme, host, port):
    a = alias_for(scheme, host, port)
    if a:                                   # aliased target -> short domain
        return f"{a}.{BASE}"
    return f"{host}.{port}.{scheme}.{BASE}"


def proxy_prefix(scheme, host, port):
    return f"http://{encode(scheme, host, port)}{PORT_SUFFIX}"


def decode(host_header):
    """Proxy hostname -> (scheme, host, port), or None if not one of ours."""
    h = host_header.split(":", 1)[0].lower().rstrip(".")
    if h == BASE or not h.endswith("." + BASE):
        return None
    label = h[: -(len(BASE) + 1)]
    if label in ALIASES:                    # short domain -> real target
        return ALIASES[label]
    parts = label.split(".")
    scheme, port = "https", None
    if parts and parts[-1] in ("http", "https", "ws", "wss"):
        scheme = parts.pop()
    if parts and parts[-1].isdigit():
        port = int(parts.pop())
    host = ".".join(parts)
    if not host:
        return None
    return scheme, host, (port if port is not None else DEFAULT_PORT[scheme])


def real_authority(scheme, host, port):
    return host if port == DEFAULT_PORT.get(scheme) else f"{host}:{port}"


# ------------------------------------------------------------- rewriters ----
# XML/SVG/XHTML namespace + DTD hosts: these URIs are identifiers, never fetched,
# so rewriting them (e.g. the SVG xmlns) only breaks rendering.
NS_HOSTS = ("www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.microsoft.com")


def _skip_host(host):
    host = host.lower()
    if host == BASE or host.endswith("." + BASE):   # already proxied -> idempotent
        return True
    return host in NS_HOSTS or host.endswith(".w3.org")


def _repl_b(m):
    host = m.group(2).decode()
    if _skip_host(host):
        return m.group(0)
    scheme = m.group(1).decode()
    port = int(m.group(3)) if m.group(3) else DEFAULT_PORT[scheme]
    return proxy_prefix(scheme, host, port).encode()


def _repl_s(m):
    host = m.group(2)
    if _skip_host(host):
        return m.group(0)
    scheme = m.group(1)
    port = int(m.group(3)) if m.group(3) else DEFAULT_PORT[scheme]
    return proxy_prefix(scheme, host, port)


def rewrite_body(b):
    return URL_RE_B.sub(_repl_b, b)


def rewrite_header(s):
    return URL_RE_S.sub(_repl_s, s)


def real_url_from_proxy(u):
    m = re.match(r'^(https?)://([^/]+)(.*)$', u)
    if not m:
        return u
    dec = decode(m.group(2))
    if not dec:
        return u
    s, host, port = dec
    real_scheme = {"ws": "http", "wss": "https"}.get(s, s)
    return f"{real_scheme}://{real_authority(s, host, port)}{m.group(3)}"


def fix_set_cookie(value, scheme, port, aliased=False):
    parts = [p.strip() for p in value.split(";")]
    out = []
    for p in parts:
        low = p.lower()
        if low == "secure":
            continue
        if low.startswith("domain="):
            # Short-domain hosts have no sub-hierarchy to map a parent domain onto,
            # so make the cookie host-only on the alias by dropping Domain.
            if aliased:
                continue
            d = p.split("=", 1)[1].strip().lstrip(".")
            out.append("Domain=" + encode(scheme, d, port))
            continue
        if low == "samesite=none":
            out.append("SameSite=Lax")
            continue
        out.append(p)
    return "; ".join(out)


def decompress(body, enc):
    enc = (enc or "").lower().strip()
    if enc in ("", "identity"):
        return body, True
    try:
        if enc == "gzip":
            return gzip.decompress(body), True
        if enc == "deflate":
            try:
                return zlib.decompress(body), True
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), True
    except Exception:
        pass
    return body, False


def sniff_html(b):
    s = b[:1024].lstrip().lower()
    return (s.startswith(b"<!doctype html") or s.startswith(b"<html")
            or s.startswith(b"<form") or s.startswith(b"<!--")
            or (s[:1] == b"<" and (b"<html" in s or b"<head" in s
                                   or b"<body" in s or b"<form" in s)))


def sniff_texty(b):
    chunk = b[:1024]
    if b"\x00" in chunk:               # NUL byte -> treat as binary
        return False
    return sniff_html(b) or chunk.lstrip()[:1] in (b"<", b"{", b"[")


# ------------------------------------------------------------- SPA shim ----
# Injected at the top of every HTML <head>. Rewrites RUNTIME urls that static
# rewriting cannot see. enc() is idempotent: only absolute urls to a real host
# are rewritten; relative / root-relative / already-proxied urls pass through.
SHIM_TEMPLATE = r"""
(function(){
  if(window.__rp)return; window.__rp=1;
  var BASE="__BASE__", PSFX="__PSFX__", AL=__ALIASES__;
  var DP={http:80,https:443,ws:80,wss:443};
  function enc(u){
    if(u==null)return u;
    try{u=String(u);}catch(e){return u;}
    var a; try{a=new URL(u, document.baseURI||location.href);}catch(e){return u;}
    var p=a.protocol.replace(':','');
    if(p!=='http'&&p!=='https'&&p!=='ws'&&p!=='wss')return u;
    var h=a.hostname.toLowerCase();
    if(h===BASE||h.slice(-(BASE.length+1))==='.'+BASE)return u;
    var port=a.port||DP[p];
    var al=AL[h+'|'+port+'|'+p];
    var eh=al?(al+'.'+BASE):(h+'.'+port+'.'+p+'.'+BASE);
    var out=(p==='ws'||p==='wss')?'ws':'http';
    return out+'://'+eh+PSFX+a.pathname+a.search+a.hash;
  }
  window.__rpEnc=enc;
  if('serviceWorker' in navigator){try{
    var SW='/__rp_sw.js', swc=navigator.serviceWorker, reg0=swc.register.bind(swc);
    swc.register=function(u,o){try{if((''+new URL(u,location.href)).indexOf(SW)<0)return reg0(SW,{scope:'/'});}catch(e){}return reg0(u,o);};
    swc.getRegistrations().then(function(rs){rs.forEach(function(r){try{var s=(r.active&&r.active.scriptURL)||'';if(s.indexOf(SW)<0)r.unregister();}catch(e){}});}).catch(function(){});
    reg0(SW,{scope:'/'}).catch(function(){});
  }catch(e){}}
  if(window.fetch){var of=window.fetch;window.fetch=function(input,init){
    try{ if(typeof input==='string'||input instanceof URL){input=enc(input);}
         else if(input&&input.url){input=new Request(enc(input.url),input);} }catch(e){}
    return of.call(this,input,init);};}
  if(window.XMLHttpRequest){var oo=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=enc(u);}catch(e){}return oo.apply(this,arguments);};}
  if(navigator.sendBeacon){var ob=navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon=function(u,d){try{u=enc(u);}catch(e){}return ob(u,d);};}
  if(window.WebSocket){var OW=window.WebSocket;
    var NW=function(u,pr){try{u=enc(u);}catch(e){}return (pr===undefined)?new OW(u):new OW(u,pr);};
    NW.prototype=OW.prototype;NW.CONNECTING=OW.CONNECTING;NW.OPEN=OW.OPEN;NW.CLOSING=OW.CLOSING;NW.CLOSED=OW.CLOSED;
    try{window.WebSocket=NW;}catch(e){}}
  ['pushState','replaceState'].forEach(function(m){var o=history[m];if(!o)return;
    history[m]=function(s,t,u){if(u!=null){try{u=enc(u);}catch(e){}}return o.call(history,s,t,u);};});
  if(window.open){var op=window.open;window.open=function(u){var a=[].slice.call(arguments);
    if(u!=null){try{a[0]=enc(u);}catch(e){}}return op.apply(window,a);};}
  try{var la=window.location.assign.bind(window.location);window.location.assign=function(u){return la(enc(u));};}catch(e){}
  try{var lr=window.location.replace.bind(window.location);window.location.replace=function(u){return lr(enc(u));};}catch(e){}
  document.addEventListener('click',function(e){var el=e.target;
    while(el&&el.tagName!=='A'&&el.tagName!=='AREA')el=el.parentNode;
    if(el&&el.href){var f=enc(el.getAttribute('href'));if(f&&f!==el.getAttribute('href'))el.href=f;}},true);
  document.addEventListener('submit',function(e){var f=e.target;
    if(f&&f.getAttribute&&f.getAttribute('action')){var n=enc(f.getAttribute('action'));if(n)f.action=n;}},true);
  ['submit','requestSubmit'].forEach(function(fn){var o=HTMLFormElement.prototype[fn];if(!o)return;
    HTMLFormElement.prototype[fn]=function(){try{var a=this.getAttribute&&this.getAttribute('action');
      if(a){var n=enc(a);if(n&&n!==a)this.action=n;}}catch(e){}return o.apply(this,arguments);};});
  function patchProp(proto,prop){try{var d=Object.getOwnPropertyDescriptor(proto,prop);if(!d||!d.set)return;
    Object.defineProperty(proto,prop,{configurable:true,enumerable:d.enumerable,get:d.get,
      set:function(v){try{v=enc(v);}catch(e){}return d.set.call(this,v);}});}catch(e){}}
  [[window.HTMLImageElement,'src'],[window.HTMLScriptElement,'src'],[window.HTMLMediaElement,'src'],
   [window.HTMLIFrameElement,'src'],[window.HTMLSourceElement,'src'],[window.HTMLTrackElement,'src'],
   [window.HTMLLinkElement,'href'],[window.HTMLAnchorElement,'href'],[window.HTMLFormElement,'action']
  ].forEach(function(x){if(x[0])patchProp(x[0].prototype,x[1]);});
  var osa=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(n,v){try{var ln=(''+n).toLowerCase();
    if(ln==='src'||ln==='href'||ln==='action'||ln==='formaction')v=enc(v);}catch(e){}
    return osa.call(this,n,v);};
})();
"""
# JS alias map for shim/SW: "host|port|scheme" -> label
ALIAS_JS = "{" + ",".join(
    '"%s|%d|%s":"%s"' % (host, port, scheme, label)
    for label, (scheme, host, port) in ALIASES.items()
) + "}"

SHIM = ("<script>" + SHIM_TEMPLATE.replace("__BASE__", BASE)
        .replace("__PSFX__", PORT_SUFFIX).replace("__ALIASES__", ALIAS_JS)
        + "</script>").encode()

# ------------------------------------------------------------- Service Worker ----
# Served at /__rp_sw.js on every encoded origin. Once controlling, it intercepts
# EVERY network request the page (and its Web Workers / dynamic imports) makes,
# regardless of how the URL was built, and routes absolute foreign URLs through
# the proxy. http://*.localhost is a secure context, so this works over plain HTTP.
SW_JS_TEMPLATE = r"""
var BASE="__BASE__", PSFX="__PSFX__", AL=__ALIASES__;
var DP={http:80,https:443,ws:80,wss:443};
function enc(raw){var u;try{u=new URL(raw);}catch(e){return raw;}
  var p=u.protocol.replace(':','');
  if(p!=='http'&&p!=='https')return raw;
  var h=u.hostname.toLowerCase();
  if(h===BASE||h.slice(-(BASE.length+1))==='.'+BASE)return raw;
  var port=u.port||DP[p];
  var al=AL[h+'|'+port+'|'+p];
  var eh=al?(al+'.'+BASE):(h+'.'+port+'.'+p+'.'+BASE);
  return 'http://'+eh+PSFX+u.pathname+u.search;}
self.addEventListener('install',function(e){self.skipWaiting();});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});
self.addEventListener('fetch',function(e){
  var req=e.request,u;
  try{u=new URL(req.url);}catch(_){return;}
  var p=u.protocol.replace(':','');
  if(p!=='http'&&p!=='https')return;
  var h=u.hostname.toLowerCase();
  if(h===BASE||h.slice(-(BASE.length+1))==='.'+BASE)return;   // already proxied
  if(req.mode==='navigate')return;                            // foreign nav can't reach us
  var target=enc(req.url);
  e.respondWith((async function(){
    try{return await fetch(new Request(target,req));}
    catch(err){return new Response('rp-sw fetch failed: '+err,{status:502});}
  })());
});
"""
SW_JS = (SW_JS_TEMPLATE.replace("__BASE__", BASE).replace("__PSFX__", PORT_SUFFIX)
         .replace("__ALIASES__", ALIAS_JS)).encode()

_HEAD_RE = re.compile(rb'<head[^>]*>', re.I)
_HTML_RE = re.compile(rb'<html[^>]*>', re.I)


def inject_shim(html):
    m = _HEAD_RE.search(html) or _HTML_RE.search(html)
    if m:
        i = m.end()
        return html[:i] + SHIM + html[i:]
    return SHIM + html


def _build_landing():
    rows = [
        "<li>http://example.com.443.https." + BASE + PORT_SUFFIX + "/</li>",
        "<li>http://example.com." + BASE + PORT_SUFFIX + "/ &nbsp;(shorthand = https:443)</li>",
    ]
    for label in sorted(ALIASES):
        href = "http://" + label + "." + BASE + PORT_SUFFIX + "/"
        rows.append(f"<li>alias: <a href='{href}'>{href}</a></li>")
    return (
        "<!doctype html><meta charset=utf-8><title>subwrap</title>"
        "<h2>subwrap (SW tier)</h2><p>Open a site as:</p>"
        "<pre>  http://HOST.PORT.SCHEME." + BASE + PORT_SUFFIX + "/PATH</pre>"
        "<p>examples:</p><ul>" + "".join(rows) + "</ul>"
    ).encode()


LANDING = _build_landing()


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "subwrap"

    def log_message(self, fmt, *args):
        pass

    def _log(self, target, status):
        sys.stdout.write(f"{self.command:6} {target} -> {status}\n")
        sys.stdout.flush()

    def _serve_sw(self):
        self.send_response_only(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Service-Worker-Allowed", "/")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(SW_JS)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(SW_JS)
        self._log(self.path, "sw.js")

    def _serve_landing(self):
        self.send_response_only(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(LANDING)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(LANDING)

    # ------------------------------------------------------ WebSocket tunnel ----
    def _tunnel_ws(self, scheme, host, port):
        upstream_tls = scheme in ("wss", "https")
        lines = [f"{self.command} {self.path} HTTP/1.1"]
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in ("accept-encoding", "content-length"):
                continue
            if kl == "host":
                v = real_authority(scheme, host, port)
            elif kl in ("origin", "referer"):
                v = real_url_from_proxy(v)
            lines.append(f"{k}: {v}")
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
        try:
            up = socket.create_connection((host, port), timeout=30)
            if upstream_tls:
                up = SSL_CTX.wrap_socket(up, server_hostname=host)
            up.sendall(req)
        except Exception as e:
            try:
                self.send_error(502, "WS upstream error", str(e))
            except Exception:
                pass
            self._log(f"WS {scheme}://{host}:{port}{self.path}", f"502 {e}")
            return
        self._log(f"WS {scheme}://{host}:{port}{self.path}", "101 tunnel")
        self.close_connection = True
        cli = self.connection
        socks = [cli, up]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 300)
                if x:
                    break
                if not r:
                    continue
                for s in r:
                    other = up if s is cli else cli
                    try:
                        data = s.recv(65536)
                    except ssl.SSLWantReadError:
                        continue
                    except Exception:
                        return
                    if not data:
                        return
                    try:
                        other.sendall(data)
                    except Exception:
                        return
                    while getattr(s, "pending", None) and s.pending():
                        try:
                            d2 = s.recv(65536)
                        except Exception:
                            return
                        if not d2:
                            return
                        other.sendall(d2)
        finally:
            try:
                up.close()
            except Exception:
                pass

    # ------------------------------------------------------ normal request ----
    def _proxy(self):
        dec = decode(self.headers.get("Host", ""))
        if dec is None:
            self._serve_landing()
            self._log(self.headers.get("Host", "?"), "landing")
            return
        scheme, host, port = dec

        if self.path.split("?", 1)[0] == "/__rp_sw.js":
            return self._serve_sw()

        dest = self.headers.get("Sec-Fetch-Dest", "").lower()
        mode = self.headers.get("Sec-Fetch-Mode", "").lower()
        is_navigation = dest in ("document", "iframe", "frame") or \
            (dest == "" and mode in ("", "navigate"))

        # Show the short domain in the browser: if an aliased target was reached via its
        # long encoded host, redirect the navigation to the short alias (same path).
        cur_alias = alias_for(scheme, host, port)
        req_host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if cur_alias and req_host != f"{cur_alias}.{BASE}" and is_navigation:
            loc = f"http://{cur_alias}.{BASE}{PORT_SUFFIX}{self.path}"
            self.send_response_only(302)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._log(f"alias {req_host} -> {cur_alias}.{BASE}", 302)
            return

        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self._tunnel_ws(scheme, host, port)

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        out = {}
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in HOP or kl in ("host", "accept-encoding", "content-length"):
                continue
            if kl in ("origin", "referer"):
                v = real_url_from_proxy(v)
            out[k] = v
        out["Host"] = real_authority(scheme, host, port)
        out["Accept-Encoding"] = "identity"
        out["X-Forwarded-Proto"] = scheme
        out["X-Forwarded-Host"] = real_authority(scheme, host, port)

        backend_tls = scheme in ("https", "wss")
        try:
            if backend_tls:
                conn = http.client.HTTPSConnection(host, port, context=SSL_CTX, timeout=30)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=30)
            conn.request(self.command, self.path, body=body or None, headers=out)
            resp = conn.getresponse()
            raw = resp.read()
        except Exception as e:
            self.send_error(502, "Bad Gateway", f"proxy error contacting {host}:{port}: {e}")
            self._log(f"{scheme}://{host}:{port}{self.path}", f"502 {e}")
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

        enc = resp.getheader("Content-Encoding", "")
        ctype = (resp.getheader("Content-Type", "") or "").lower()
        payload, decoded = decompress(raw, enc)
        # Some servers (e.g. SAML auto-POST pages) omit Content-Type. Sniff so we
        # still rewrite + inject instead of letting raw absolute URLs slip through.
        sniffable = ctype == "" or ctype.startswith("application/octet-stream")
        is_text = any(h in ctype for h in TEXT_HINTS) or (sniffable and sniff_texty(payload))
        is_html = "text/html" in ctype or (sniffable and sniff_html(payload))
        # Inject the shim ONLY into real navigations (is_navigation computed above).
        # XHR/fetch responses often carry text/html but are parsed as data (e.g.
        # PortalGuard's XML agent response) -- prepending <script> corrupts them.
        if decoded and is_text:
            payload = rewrite_body(payload)
        if decoded and is_html and is_navigation:
            payload = inject_shim(payload)

        self.send_response_only(resp.status, resp.reason)
        for name, value in resp.getheaders():
            nl = name.lower()
            if nl in DROP_RESP or nl == "content-length":
                continue
            if nl == "content-encoding" and decoded:
                continue
            if nl in ("location", "link", "refresh", "content-location"):
                value = rewrite_header(value)
            elif nl == "set-cookie":
                value = fix_set_cookie(rewrite_header(value), scheme, port,
                                       aliased=cur_alias is not None)
            elif nl == "access-control-allow-origin" and value.strip() != "*":
                value = rewrite_header(value)   # real origin -> encoded origin
            self.send_header(name, value)

        send_body = self.command != "HEAD" and resp.status not in (204, 304)
        self.send_header("Content-Length", str(len(payload) if send_body else 0))
        self.end_headers()
        if send_body:
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self._log(f"{scheme}://{host}:{port}{self.path}", resp.status)

    do_GET = do_POST = do_PUT = do_DELETE = _proxy
    do_PATCH = do_HEAD = do_OPTIONS = _proxy


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # On Windows, SO_REUSEADDR lets a second server bind a port another one is already
    # listening on: both start without error and Windows keeps handing connections to
    # just one of them (e.g. a stale proxy left on :80 silently answers everything).
    # So bind exclusively there; elsewhere SO_REUSEADDR only permits rebinding while
    # old connections sit in TIME_WAIT, which is what we want for quick restarts.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class ThreadingHTTPServer6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def make_server(addr):
    cls = ThreadingHTTPServer6 if ":" in addr else ThreadingHTTPServer
    return cls((addr, LISTEN_PORT), ProxyHandler)


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)      # banner visible even when piped
    except Exception:
        pass
    print(f"  subwrap (SW tier)  ->  *.{BASE}{PORT_SUFFIX}")
    print(f"  config: {_CFG['config_path']}")
    if ALIASES:
        for label, (s, h, p) in sorted(ALIASES.items()):
            print(f"  alias:  http://{label}.{BASE}{PORT_SUFFIX}/  ->  {s}://{real_authority(s, h, p)}/")
    else:
        print(f"  open e.g. http://example.com.443.https.{BASE}{PORT_SUFFIX}/")
    lan = any(a in ("0.0.0.0", "::") for a in BIND_ADDRS)
    if lan:
        print("  WARNING: bound to all interfaces -- this is an OPEN proxy on your network.")
    if lan and not BASE.endswith(".localhost"):
        print("  NOTE: base is not *.localhost, so Service Workers won't register over plain HTTP"
              " (other layers still work).")
    # Bind everything here, before any serving thread starts, so a failed bind is
    # reported (and can stop us) instead of printing a bogus "listening" line.
    servers, in_use = [], False
    for addr in BIND_ADDRS:
        label = f"[{addr}]" if ":" in addr else addr
        try:
            servers.append((label, make_server(addr)))
        except Exception as e:
            print(f"  could not bind {label}:{LISTEN_PORT}: {e}")
            if isinstance(e, OSError) and e.errno == errno.EADDRINUSE:
                in_use = True
    if in_use:
        # Another program is serving that address; clients reaching it would get that
        # program instead of us, so don't run half-shadowed.
        print(f"  FATAL: port {LISTEN_PORT} is already in use by another program"
              " (an older proxy still running?)")
        sys.exit(1)
    if not servers:
        print("  FATAL: could not bind any address")
        sys.exit(1)
    started = []
    for label, srv in servers:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        started.append(t)
        print(f"  listening on {label}:{LISTEN_PORT}")
    print("  ready. Ctrl+C to stop.")
    try:
        for t in started:
            t.join()
    except KeyboardInterrupt:
        print("\n  stopped.")


if __name__ == "__main__":
    main()
