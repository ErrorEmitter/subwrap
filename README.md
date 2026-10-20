# subwrap

A tiny, zero-dependency local reverse proxy that makes **any website or internal
service reachable under a subdomain of a local base domain** — so you can browse
and test it over plain `http://…localhost` while the browser only ever talks to
the proxy.

```
http://<host>.<port>.<scheme>.rp.localhost/<path>   ->   <scheme>://<host>:<port>/<path>

http://example.com.443.https.rp.localhost/          ->   https://example.com/
http://a.internal.8080.https.rp.localhost/app       ->   https://a.internal:8080/app
```

It is **whole-site, cross-site, SPA and WebSocket aware**: links, redirects,
runtime `fetch`/XHR, and even requests made from Web Workers all stay inside the
proxy. Single file, Python standard library only.

> **For local development and testing only.** See [Security](#security). Only
> proxy services you own or are authorized to test.

## Why

Reverse-proxying one hardcoded backend is easy (relative URLs just work). Making
a *generic* proxy is hard because a path-based `/<url>` scheme loses the target
on every root-relative link. subwrap puts the full target **in the host** instead,
so the browser resolves relative URLs correctly on its own and each target keeps
an isolated origin (cookies, `localStorage`, CORS).

Typical uses: exercising a staging/SSO/SAML login flow locally, testing a SPA
against a real backend under a clean domain, or reaching an internal HTTPS
service from a browser that only speaks plain HTTP.

## How it works

The target `scheme://host:port` is encoded into the subdomain labels
`host.port.scheme.<base>`. The proxy decodes the `Host` header, fetches the real
target, and returns the response — rewriting anything that would otherwise leak
the real origin or break over plain HTTP. Four layers, each catching what the
previous can't:

1. **Static rewrite** — absolute URLs, `Location`/redirects, `Set-Cookie`
   (`Domain` re-encoded, `Secure` dropped, `SameSite=None`→`Lax`), CORS headers;
   `HSTS`/`CSP` stripped so the browser isn't forced back to HTTPS.
2. **JS shim** injected into navigations — wraps `fetch` / `XHR` / `sendBeacon` /
   `WebSocket` / `history` / `window.open` / `location.assign|replace` / anchor &
   form navigation / dynamic element `src|href|action`, rewriting runtime URLs.
3. **Service Worker** — intercepts *every* network request the page and its Web
   Workers make, regardless of how the URL was built (works because
   `*.localhost` is a secure context over HTTP).
4. **WebSocket tunnel** — `ws`/`wss` are proxied through.

Relative and root-relative URLs are left untouched — they already resolve
correctly against the encoded origin.

## Requirements

Python 3.x — standard library only, no `pip install`.

## Quick start

```bash
git clone https://github.com/ErrorEmitter/subwrap.git
cd subwrap
cp subwrap.example.ini subwrap.ini      # optional; defaults work without it
python subwrap.py
```

Then open, e.g.:

```
http://example.com.443.https.rp.localhost/
```

Port 80 keeps URLs clean (no `:port`). On most systems `*.localhost` already
resolves to loopback with no hosts-file edit.

## Configuration

Everything site-specific lives in `subwrap.ini` (gitignored). Pass a different
path as the first argument: `python subwrap.py /path/to.ini`.

```ini
[server]
base = rp.localhost      # base domain (keep *.localhost so Service Workers work)
port = 80                # listen port (80 = no :port in URLs)
bind = loopback          # loopback | all | explicit addrs (e.g. 192.168.1.50, ::1)

[aliases]
# <short-label> = <target-url>
example = https://example.com
```

## Short domains (aliases)

An alias gives a target a one-label name and makes it the name shown in the
browser:

```ini
[aliases]
app = https://app.internal:8443
```

`http://app.rp.localhost/` now serves `https://app.internal:8443/`, every rewrite
emits the short form, and the long encoded form redirects to it.

## LAN access

To reach the proxy (and internal services) from other machines, set a routable
base and bind to the network:

```ini
[server]
base = rp.my-host.local
port = 80
bind = all
```

With wildcard DNS for `*.rp.my-host.local` pointing at the host, a client can open:

```
http://git.corp.lan.443.https.rp.my-host.local/   ->   https://git.corp.lan/
```

Caveats:

- **Service Workers need `*.localhost`.** A non-`.localhost` base over plain HTTP
  is not a secure context, so layer 3 is disabled there; layers 1, 2 and 4 still
  work.
- **Wildcard DNS** is required (plain mDNS has no wildcards) — run a small DNS
  server or add per-name hosts entries on the clients.
- `bind = all` exposes an **open proxy** — see below.

## Limitations

- `location.href = 'https://other-host'` assigned as a raw string to a *foreign*
  absolute URL can't be intercepted (host-object setter; cross-origin navigation
  isn't service-worker-visible). Relative, `assign`/`replace`, links and forms are
  fine.
- The target's own Service Worker is unregistered/blocked so subwrap's can
  control the page; the target's offline/PWA features are therefore disabled.
- WebSocket tunnelling is best-effort (raw byte bridge).
- Backend TLS certificates are **not verified** (local testing convenience).

## Security

subwrap deliberately weakens transport protections so a site works over plain
local HTTP: it strips `HSTS`/`CSP`, drops the `Secure` cookie flag, and does not
verify backend certificates. Consequences:

- **Do not expose it to untrusted networks.** `bind = all` turns it into an open
  reverse proxy that anyone who can reach the port can use to fetch arbitrary
  sites through your machine. Keep it on `loopback` unless you understand this.
- **For local development and testing only.** Only proxy services you own or are
  explicitly authorized to test. Don't use it against third parties' login flows.

## License

MIT — see [LICENSE](LICENSE).
