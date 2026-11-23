#!/usr/bin/env python3
"""xproxy - the distro's built-in internet proxy and custom webapp host.

* Forward HTTP proxy + HTTPS CONNECT tunnelling (system-wide, 127.0.0.1:8080)
* Hosts custom webapps: http://<name>.app.local/ -> <webapps dir>/<name>/
  (no DNS needed: the browser sends *.app.local to this proxy)
* Optional reverse-proxy of an app name to a local backend ([upstreams])
* Host block list ([filter] block = pattern, pattern, ...)
"""
import asyncio
import configparser
import json
import mimetypes
import os
import time
import urllib.parse
from fnmatch import fnmatch

CONF = os.environ.get("XPROXY_CONF", "/etc/xfceproxy/proxy.conf")
cfg = configparser.ConfigParser()
cfg.read(CONF)

LISTEN = cfg.get("proxy", "listen", fallback="127.0.0.1")
PORT = cfg.getint("proxy", "port", fallback=8080)
LOG = cfg.get("proxy", "log", fallback="")
APPS_DIR = cfg.get("webapps", "dir", fallback="/usr/share/xfceproxy/webapps")
DOMAIN = cfg.get("webapps", "domain", fallback="app.local")
DEFAULT_APP = cfg.get("webapps", "default", fallback="home")
BLOCK = [p.strip() for p in cfg.get("filter", "block", fallback="").split(",") if p.strip()]
EDU_FLAG = os.environ.get("XPROXY_MODE_FILE", "/etc/xfceproxy/mode")
EDU_ALLOW = [p.strip() for p in cfg.get("edu", "allow", fallback="").split(",") if p.strip()]


EXTRA_FILE = os.environ.get("XPROXY_EXTRA", "/etc/xfceproxy/extra-allow")


def edu_blocked(host):
    """In EDU Mode only the sites on the allow-list (plus local webapps) can be reached."""
    try:
        with open(EDU_FLAG) as f:
            if f.read().strip() != "edu":
                return False
    except OSError:
        return False
    h = host.lower()
    try:
        with open(EXTRA_FILE) as f:
            extra = [x.strip().lower() for x in f if x.strip()]
    except OSError:
        extra = []
    return not (any(h == x or h.endswith("." + x) for x in extra) or h in ("localhost", "127.0.0.1") or h == DOMAIN or h.endswith("." + DOMAIN) or any(fnmatch(h, x) for x in EDU_ALLOW))


UPSTREAMS = dict(cfg.items("upstreams")) if cfg.has_section("upstreams") else {}


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    if LOG:
        try:
            with open(LOG, "a") as f:
                f.write(line + "\n")
            return
        except OSError:
            pass
    print(line, flush=True)


def respond(status, body=b"", ctype="text/html; charset=utf-8"):
    reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 502: "Bad Gateway"}
    head = (f"HTTP/1.1 {status} {reasons.get(status, 'OK')}\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode()
    return head + body


def app_for_host(host):
    """Return the webapp name for a Host header, or None if it's a normal site."""
    host = host.lower().split(":")[0]
    if host in ("localhost", "127.0.0.1", "xfceproxy", DOMAIN):
        return DEFAULT_APP
    if host.endswith("." + DOMAIN):
        return host[: -(len(DOMAIN) + 1)]
    return None


def serve_static(app, path):
    root = os.path.realpath(os.path.join(APPS_DIR, app))
    rel = urllib.parse.unquote(path.split("?", 1)[0].split("#", 1)[0]).lstrip("/")
    fp = os.path.realpath(os.path.join(root, rel))
    if os.path.isdir(fp):
        fp = os.path.join(fp, "index.html")
    if not (fp == root or fp.startswith(root + os.sep)):
        return respond(403, b"Forbidden")
    if not os.path.isfile(fp):
        return respond(404, f"<h1>404</h1><p>No such webapp file: {app}</p>".encode())
    ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
    with open(fp, "rb") as f:
        return respond(200, f.read(), ctype)


async def pipe(src, dst):
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except Exception:
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


def split_hostport(hp, default_port):
    if hp.startswith("["):  # IPv6 literal
        host, _, rest = hp[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    host, sep, port = hp.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return hp, default_port


async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        lines = head.decode("latin1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    except Exception:
        writer.close()
        return

    try:
        # ---- HTTPS tunnel -------------------------------------------------
        if method == "CONNECT":
            host, port = split_hostport(target, 443)
            if any(fnmatch(host.lower(), p) for p in BLOCK) or edu_blocked(host):
                log(f"{peer[0]} BLOCK {target}")
                writer.write(respond(403, b"This site is blocked or is not available in EDU Mode."))
                await writer.drain()
                writer.close()
                return
            try:
                ur, uw = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(respond(502, b"Bad gateway"))
                await writer.drain()
                writer.close()
                return
            log(f"{peer[0]} CONNECT {target}")
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(pipe(reader, uw), pipe(ur, writer))
            return

        # ---- Plain HTTP: figure out host + path ---------------------------
        if target.startswith("http://"):
            u = urllib.parse.urlsplit(target)
            host_hdr = u.netloc
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        else:
            host_hdr = headers.get("host", "")
            path = target

        host, port = split_hostport(host_hdr, 80)

        # Custom webapp?
        app = app_for_host(host)
        if app is not None:
            if path.split("?", 1)[0] == "/_apps":
                names = sorted(d for d in (os.listdir(APPS_DIR) if os.path.isdir(APPS_DIR) else [])
                               if os.path.isfile(os.path.join(APPS_DIR, d, "index.html")))
                writer.write(respond(200, json.dumps(names).encode(), "application/json"))
                await writer.drain()
                writer.close()
                return
            if app in UPSTREAMS:
                uh, up = split_hostport(UPSTREAMS[app], 80)
                ur, uw = await asyncio.open_connection(uh, up)
                out = [f"{method} {path} {version}"]
                out += [f"{k}: {v}" for k, v in headers.items()
                        if k not in ("connection", "proxy-connection")]
                out += ["Connection: close", "", ""]
                uw.write("\r\n".join(out).encode("latin1"))
                await uw.drain()
                log(f"{peer[0]} APP-PROXY {app} {path}")
                await asyncio.gather(pipe(reader, uw), pipe(ur, writer))
                return
            log(f"{peer[0]} APP {app} {path}")
            writer.write(serve_static(app, path))
            await writer.drain()
            writer.close()
            return

        # Block list
        if any(fnmatch(host.lower(), p) for p in BLOCK) or edu_blocked(host):
            log(f"{peer[0]} BLOCK {host}")
            writer.write(respond(403, b"This site is blocked or is not available in EDU Mode."))
            await writer.drain()
            writer.close()
            return

        # Forward to the real internet
        ur, uw = await asyncio.open_connection(host, port)
        out = [f"{method} {path} {version}"]
        out += [f"{k}: {v}" for k, v in headers.items()
                if k not in ("connection", "proxy-connection")]
        out += ["Connection: close", "", ""]
        uw.write("\r\n".join(out).encode("latin1"))
        await uw.drain()
        log(f"{peer[0]} {method} {host}{path}")
        await asyncio.gather(pipe(reader, uw), pipe(ur, writer))
    except Exception as e:
        log(f"{peer[0]} ERROR {e!r}")
        try:
            writer.write(respond(502, b"Bad gateway"))
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, LISTEN, PORT)
    log(f"xproxy listening on {LISTEN}:{PORT}, webapps={APPS_DIR}, domain=*.{DOMAIN}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
