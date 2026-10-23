#!/usr/bin/env python3
"""Port Checker: a small local web UI for checking which TCP ports accept connections.

Run it with:

    python3 port_checker.py            # opens http://127.0.0.1:8765 in your browser
    python3 port_checker.py --port 9000 --no-browser

Uses only the Python standard library (3.8+). The server listens on 127.0.0.1 only,
so nobody else on your network can use it to probe hosts through your machine.

How the pieces fit together:
  1. main() starts a small web server on 127.0.0.1 and opens the page (PAGE) in your browser.
  2. When you press "Check ports", the page sends the host, ports and timeout to /api/check.
  3. Handler.do_POST() validates them (normalize_host, parse_ports, parse_timeout, resolve),
     then runs check_port() on many ports at once using a thread pool.
  4. Each result is sent back the moment it finishes, one JSON line at a time, and the
     JavaScript in PAGE updates the panel and the table as results arrive.

Only check hosts you own or are authorized to test.
"""

import argparse
import json
import math
import re
import socket
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_PORTS = 1024          # most ports allowed in one check
MAX_WORKERS = 100         # parallel connection attempts per check
DEFAULT_TIMEOUT = 1.0     # seconds
MIN_TIMEOUT, MAX_TIMEOUT = 0.1, 300.0
LOCAL_NAMES = {"127.0.0.1", "localhost", "[::1]"}

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "submission", 631: "ipp",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3000: "dev-server", 3306: "mysql", 3389: "rdp",
    5000: "dev-server", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
    5985: "winrm", 5986: "winrm-https", 6379: "redis", 6443: "kubernetes",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "prometheus", 9200: "elasticsearch", 9418: "git",
    11211: "memcached", 27017: "mongodb",
}
NAME_TO_PORT = {name: port for port, name in SERVICES.items()}
NAME_TO_PORT.update({"postgres": 5432, "mongo": 27017, "http": 80, "https": 443})


# --------------------------------------------------------------------------- checks

def service_name(port):
    """Return the usual service name for a port number (22 -> "ssh"), or "" if unknown.

    Checks the SERVICES table first, then asks the operating system's services list.
    """
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def check_port(addrinfo, port, timeout):
    """Try one TCP connection to `port` and report what happened.

    This is the original script's check_port(), extended to tell the outcomes apart.
    `addrinfo` is the resolved address from resolve(); only the port number is swapped in.
    `timeout` is how many seconds to wait for an answer.

    Returns a dict (port, state, time taken in ms, error detail) that is sent straight
    to the page. The state is one of:

    open      - the connection was accepted
    closed    - the host refused it (reachable, nothing listening)
    filtered  - no answer before the timeout (often a firewall dropping packets)
    error     - the network reported an error, e.g. no route to host
    """
    family, socktype, proto, _, sockaddr = addrinfo
    target = (sockaddr[0], port) + tuple(sockaddr[2:])
    detail = ""
    start = time.perf_counter()
    try:
        with socket.socket(family, socktype, proto) as s:
            s.settimeout(timeout)
            s.connect(target)
        state = "open"
    except ConnectionRefusedError:
        state = "closed"
    except socket.timeout:
        state = "filtered"
    except OSError as exc:
        state = "error"
        detail = exc.strerror or str(exc)
    ms = (time.perf_counter() - start) * 1000
    return {"type": "result", "port": port, "state": state,
            "ms": round(ms, 2), "detail": detail}


# --------------------------------------------------------------------------- input

def normalize_host(raw):
    """Clean up what was typed in the Host box and return a bare host name or IP.

    Accepts a pasted URL ("http://example.com/path" -> "example.com") and IPv6 in
    brackets ("[::1]" -> "::1"). Raises ValueError, with a message the page shows
    as-is, when the box is empty, includes a port ("example.com:8080"), or isn't valid.
    """
    host = str(raw or "").strip()
    if "://" in host:                      # someone pasted a URL
        host = urlsplit(host).hostname or ""
    else:
        host = host.split("/")[0]
    if host.startswith("[") and "]" in host:
        if host.endswith("]"):
            host = host[1:-1]
        else:
            raise ValueError("Enter the host without a port number, and put ports in the Ports box.")
    elif host.count(":") == 1:
        raise ValueError("Enter the host without a port number, and put ports in the Ports box.")
    if not host:
        raise ValueError("Enter a host name or IP address.")
    if len(host) > 253 or any(c.isspace() for c in host):
        raise ValueError("That host name isn't valid.")
    return host


def parse_ports(text):
    """Turn the Ports box into a sorted list of unique port numbers.

    Understands single ports ("22"), ranges ("8000-8010" or "8000 - 8010") and service
    names ("ssh"), separated by commas, spaces or semicolons. Raises ValueError for an
    empty box, an unknown name, a port outside 1-65535, or more than MAX_PORTS ports.
    """
    text = re.sub(r"\s*-\s*", "-", str(text or ""))
    parts = [p for p in re.split(r"[\s,;]+", text.strip()) if p]
    if not parts:
        raise ValueError("Enter at least one port, such as 22 or 8000-8010.")
    ports = set()
    for part in parts:
        match = re.fullmatch(r"(\d+)-(\d+)", part)
        if match:
            lo, hi = sorted((int(match.group(1)), int(match.group(2))))
        elif part.isdigit():
            lo = hi = int(part)
        else:
            name = part.lower()
            if name in NAME_TO_PORT:
                lo = hi = NAME_TO_PORT[name]
            else:
                try:
                    lo = hi = socket.getservbyname(name, "tcp")
                except OSError:
                    raise ValueError(f"“{part}” isn't a port number or a known service name.")
        if lo < 1 or hi > 65535:
            raise ValueError(f"{part} is outside the valid port range (1-65535).")
        ports.update(range(lo, hi + 1))
        if len(ports) > MAX_PORTS:
            total = len(ports)
            raise ValueError(f"That's {total:,} ports. The limit is {MAX_PORTS:,} per check, "
                             "so split it into smaller batches.")
    return sorted(ports)


def parse_timeout(value):
    """Convert the Timeout box to seconds (a float).

    Raises ValueError if it isn't a number or falls outside MIN_TIMEOUT to MAX_TIMEOUT.
    """
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        raise ValueError("Timeout must be a number of seconds.")
    if not math.isfinite(timeout) or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"Timeout must be between {MIN_TIMEOUT:g} and {MAX_TIMEOUT:g} seconds.")
    return timeout


def resolve(host):
    """Look up a host name once, before any ports are checked.

    Returns one address record from socket.getaddrinfo(), preferring IPv4 the way the
    original script did. Raises ValueError if the name can't be found.
    """
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Couldn't find a host named “{host}”. Check the spelling, or use an IP address.")
    except UnicodeError:
        raise ValueError("That host name isn't valid.")
    ipv4 = [info for info in infos if info[0] == socket.AF_INET]
    return (ipv4 or infos)[0]      # prefer IPv4, like the original script


# --------------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    """Answers the browser's requests. One instance handles one request.

    GET  /           -> the web page
    POST /api/check  -> runs a check and streams the results back
    """
    server_version = "PortChecker"
    sys_version = ""

    def log_message(self, fmt, *args):
        """Silence the default one-line-per-request log so the terminal stays readable."""
        pass

    def _trusted(self):
        """Return True if the request came from this app's own page on this computer.

        Checks the Host header (blocks DNS-rebinding tricks) and the Origin header
        (blocks other websites from sending requests to this server). If the request
        fails either check, sends a 403 error and returns False.
        """
        host = self.headers.get("Host", "")
        if host.startswith("[") and "]" in host:
            name = host[: host.index("]") + 1]
        else:
            name = host.rsplit(":", 1)[0]
        ok = name.lower() in LOCAL_NAMES
        origin = self.headers.get("Origin")
        if ok and origin is not None:
            ok = origin != "null" and urlsplit(origin).netloc.lower() == host.lower()
        if not ok:
            self._json(403, {"error": "Requests are only accepted from this computer."})
        return ok

    def _json(self, code, obj):
        """Send a complete JSON response with the given HTTP status code.

        Used for errors, e.g. _json(400, {"error": "..."}), which the page displays.
        """
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Serve the web page at "/", an empty favicon, and 404 for anything else."""
        if not self._trusted():
            return
        path = urlsplit(self.path).path
        if path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self._json(404, {"error": "Not found."})

    def do_POST(self):
        """Run a port check for the page and stream the results back.

        1. Read and validate the JSON body: {"host": ..., "ports": ..., "timeout": ...}.
           Any problem is returned as a 400 error message instead.
        2. Check all ports in parallel (up to MAX_WORKERS at a time).
        3. Write one JSON line per event as it happens:
             {"type": "start", ...}   the host, its IP and the list of ports
             {"type": "result", ...}  one per port, in the order they finish
             {"type": "done", ...}    total time taken
        If the page presses Stop, the connection drops and remaining checks are cancelled.
        """
        if not self._trusted():
            return
        if urlsplit(self.path).path != "/api/check":
            return self._json(404, {"error": "Not found."})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._json(415, {"error": "Expected a JSON request."})
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if not 0 < length <= 16384:
            return self._json(400, {"error": "The request was empty or too large."})

        try:
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise TypeError
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return self._json(400, {"error": "Couldn't read the request."})
        try:
            host = normalize_host(data.get("host"))
            ports = parse_ports(data.get("ports"))
            timeout = parse_timeout(data.get("timeout", DEFAULT_TIMEOUT))
            addrinfo = resolve(host)
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})

        # Stream one JSON object per line so the page can update as results arrive.
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        started = time.perf_counter()
        pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ports)))
        futures = [pool.submit(check_port, addrinfo, p, timeout) for p in ports]
        try:
            self._line({"type": "start", "host": host, "ip": addrinfo[4][0],
                        "ports": [{"port": p, "service": service_name(p)} for p in ports]})
            for fut in as_completed(futures):
                self._line(fut.result())
            self._line({"type": "done", "elapsed": round(time.perf_counter() - started, 3)})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass                              # the page pressed Stop or was closed
        finally:
            for fut in futures:
                fut.cancel()
            pool.shutdown(wait=False)

    def _line(self, obj):
        """Send one JSON object followed by a newline, immediately, to the page."""
        self.wfile.write((json.dumps(obj) + "\n").encode())


class Server(ThreadingHTTPServer):
    """The web server. Handles each request on its own thread, so a long check
    doesn't freeze the page, and those threads stop when the program exits."""
    daemon_threads = True
    # On Windows SO_REUSEADDR lets two servers share a port, which hides "port in use".
    allow_reuse_address = sys.platform != "win32"


def main():
    """Start the app: read command-line options, start the server, open the browser.

    If the chosen UI port is busy it tries the next 9. Runs until you press Ctrl+C.
    """
    parser = argparse.ArgumentParser(description="Local web UI for checking TCP ports.")
    parser.add_argument("--port", type=int, default=8765,
                        help="port for the web UI (default 8765; tries the next 9 if taken)")
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    args = parser.parse_args()

    server, last_error = None, None
    for ui_port in range(args.port, args.port + 10):
        try:
            server = Server(("127.0.0.1", ui_port), Handler)
            break
        except OSError as exc:
            last_error = exc
    if server is None:
        sys.exit(f"Couldn't start the web UI on ports {args.port}-{args.port + 9}: {last_error}\n"
                 "Try another one with --port.")

    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Port checker is running at {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


# --------------------------------------------------------------------------- page

# Content-Security-Policy for the page: it may only talk to this server and load
# Google Fonts, and other sites can't embed it in a frame.
CSP = ("default-src 'self'; script-src 'unsafe-inline'; "
       "style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

# The whole web page (HTML, CSS and JavaScript) served at "/". It's kept in this file
# so the app is a single file you can copy anywhere.
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port Checker</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='2' y='6' width='28' height='20' rx='3' fill='%233B424B'/%3E%3Crect x='9' y='10' width='14' height='4' rx='1.5' fill='%2346D37D'/%3E%3Cpath d='M8 17h16v4h-5v3h-6v-3H8z' fill='%23121518'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600&family=Barlow+Semi+Condensed:wght@500;600&display=swap" rel="stylesheet">
<style>
:root {
  --page:#ECEEF1; --surface:#FFFFFF; --ink:#1B2129; --muted:#56606B; --line:#CBD1D8;
  --plate:#3B424B; --plate-hi:#4B535D; --plate-lo:#2B3137; --plate-text:#C8CFD6; --jack:#121518;
  --led-off:#555D66; --open:#46D37D; --amber:#F2AE3D; --red:#EE5A50;
  --open-ink:#17723D; --amber-ink:#8A5000; --red-ink:#B3261E;
  --focus:#2F62D6; --btn:#1B2129; --btn-ink:#FFFFFF;
  --sans:'Barlow', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --cond:'Barlow Semi Condensed', 'Barlow', system-ui, -apple-system, 'Segoe UI', sans-serif;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --page:#111519; --surface:#192026; --ink:#E3E8ED; --muted:#9AA4AE; --line:#2E363E;
    --plate:#2B3138; --plate-hi:#38404A; --plate-lo:#1C2126; --plate-text:#B2BBC4; --jack:#0A0C0E;
    --led-off:#424A53; --open-ink:#5CD98E; --amber-ink:#F2B04A; --red-ink:#F2827A;
    --focus:#7FA4FF; --btn:#E3E8ED; --btn-ink:#111519;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --page:#111519; --surface:#192026; --ink:#E3E8ED; --muted:#9AA4AE; --line:#2E363E;
  --plate:#2B3138; --plate-hi:#38404A; --plate-lo:#1C2126; --plate-text:#B2BBC4; --jack:#0A0C0E;
  --led-off:#424A53; --open-ink:#5CD98E; --amber-ink:#F2B04A; --red-ink:#F2827A;
  --focus:#7FA4FF; --btn:#E3E8ED; --btn-ink:#111519;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--page); color:var(--ink); font:400 16px/1.5 var(--sans); -webkit-font-smoothing:antialiased; }
.wrap { max-width:1000px; margin:0 auto; padding:44px 16px 72px; }

h1 { font:600 2.125rem/1.1 var(--cond); letter-spacing:-0.01em; margin:0 0 6px; }
.intro p { margin:0; color:var(--muted); max-width:62ch; }

/* form */
.controls { display:grid; grid-template-columns:minmax(0,1.1fr) minmax(0,2fr) 128px auto; gap:12px; align-items:end; margin-top:28px; }
.field label { display:block; font-weight:500; font-size:.875rem; margin-bottom:4px; }
.field input { width:100%; height:44px; padding:0 12px; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:var(--ink); font:inherit; }
.field input:hover { border-color:var(--muted); }
.ports input { font-variant-numeric:tabular-nums; }
:focus-visible { outline:2px solid var(--focus); outline-offset:2px; }
.run { height:44px; min-width:136px; padding:0 22px; border:1px solid var(--btn); border-radius:6px; background:var(--btn); color:var(--btn-ink); font:600 1rem var(--sans); cursor:pointer; }
.run.stop { background:transparent; color:var(--ink); border-color:var(--ink); }
.hint { grid-column:2 / -1; margin:-6px 0 0; font-size:.875rem; color:var(--muted); }
.presets { grid-column:1 / -1; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
.presets > span { font-size:.875rem; color:var(--muted); margin-right:2px; }
.presets button { padding:5px 13px; border:1px solid var(--line); border-radius:999px; background:transparent; color:var(--ink); font:500 .875rem var(--sans); cursor:pointer; }
.presets button:hover { border-color:var(--muted); background:var(--surface); }

.error { margin:20px 0 0; padding:10px 14px; border-left:3px solid var(--red-ink); background:var(--surface); border-radius:0 6px 6px 0; }

/* the faceplate */
.plate { position:relative; margin-top:28px; padding:14px 52px 20px; border-radius:4px; color:var(--plate-text);
  background:linear-gradient(var(--plate-hi), var(--plate) 14%, var(--plate) 86%, var(--plate-lo));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 1px 2px rgba(0,0,0,.22), 0 6px 18px -10px rgba(0,0,0,.45); }
.plate::before, .plate::after { content:""; position:absolute; top:50%; width:10px; height:18px; margin-top:-9px; border-radius:5px; background:var(--jack); box-shadow:inset 0 1px 2px rgba(0,0,0,.7), 0 1px 0 rgba(255,255,255,.06); }
.plate::before { left:20px; }
.plate::after { right:20px; }
.plate-head { display:flex; justify-content:space-between; gap:16px; margin-bottom:12px; font:500 .875rem/1.3 var(--cond); }
#plate-host { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
#plate-count { font-variant-numeric:tabular-nums; white-space:nowrap; }
.jacks { display:flex; flex-wrap:wrap; gap:14px 10px; min-height:66px; }
.plate-empty { align-self:center; margin:0; font-size:.9375rem; }
.jack { width:44px; display:flex; flex-direction:column; align-items:center; gap:5px; }
.num { font:600 .8125rem/1 var(--cond); font-variant-numeric:tabular-nums; }
.led { display:block; width:16px; height:5px; border-radius:2px; background:var(--led-off); transition:background-color .2s, box-shadow .2s; }
.socket { width:34px; height:28px; background:repeating-linear-gradient(90deg, rgba(204,170,98,.85) 0 1px, transparent 1px 3px) 50% 4px / 21px 6px no-repeat, var(--jack);
  clip-path:polygon(0 0, 100% 0, 100% 72%, 68% 72%, 68% 100%, 32% 100%, 32% 72%, 0 72%); }
.jack[data-state="skipped"] { opacity:.45; }
.plate.dense .jacks { gap:5px; min-height:0; }
.plate.dense .jack { width:auto; }
.plate.dense .num, .plate.dense .socket { display:none; }
.plate.dense .led { width:12px; height:12px; border-radius:2px; }
.progress { position:absolute; left:0; right:0; bottom:0; height:3px; overflow:hidden; border-radius:0 0 4px 4px; }
#progress { display:block; height:100%; width:0; background:var(--plate-text); opacity:.55; transition:width .15s linear, opacity .5s .5s; }
.plate.complete #progress { opacity:0; }

/* states, shared by faceplate, tally and table */
[data-state="pending"] .led { background:var(--plate-text); animation:blink .8s steps(1) infinite; }
[data-state="open"] .led { background:var(--open); }
[data-state="filtered"] .led { background:var(--amber); }
[data-state="error"] .led { background:var(--red); }
.plate [data-state="open"] .led { box-shadow:0 0 7px 1px rgba(70,211,125,.6); }
.plate [data-state="filtered"] .led { box-shadow:0 0 7px 1px rgba(242,174,61,.5); }
.plate [data-state="error"] .led { box-shadow:0 0 7px 1px rgba(238,90,80,.5); }
.plate [data-state="open"] .num { color:#fff; }
@keyframes blink { 50% { background:var(--led-off); } }

.tally { display:flex; flex-wrap:wrap; gap:6px 22px; margin-top:14px; font-size:.9375rem; }
.tally .t { display:inline-flex; align-items:center; gap:8px; }
.tally .led { width:10px; height:10px; border-radius:50%; }
.tally [data-state="closed"] .led { background:var(--muted); opacity:.55; }
.tally b { font-weight:600; font-variant-numeric:tabular-nums; }
.tally.idle b { display:none; }

/* results table */
.results { margin-top:30px; }
.results-bar { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px 20px; margin-bottom:12px; }
.summary { margin:0; font-weight:500; }
.actions { display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; }
.toggle { display:inline-flex; align-items:center; gap:8px; font-size:.9375rem; cursor:pointer; margin-right:6px; }
.toggle input { width:18px; height:18px; margin:0; accent-color:var(--btn); }
.ghost { height:36px; padding:0 14px; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:var(--ink); font:500 .9375rem var(--sans); cursor:pointer; }
.ghost:hover:not(:disabled) { border-color:var(--muted); }
.ghost:disabled { opacity:.5; cursor:default; }
.table-wrap { max-height:min(70vh, 760px); overflow:auto; border:1px solid var(--line); border-radius:6px; background:var(--surface); }
table { width:100%; border-collapse:separate; border-spacing:0; }
th, td { padding:9px 16px; text-align:left; border-bottom:1px solid var(--line); white-space:nowrap; }
th { position:sticky; top:0; z-index:1; background:var(--surface); font-weight:600; font-size:.875rem; color:var(--muted); }
tbody tr:last-child td { border-bottom:0; }
td.port { font-weight:600; font-variant-numeric:tabular-nums; }
td.svc { color:var(--muted); }
td.res .led { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:9px; vertical-align:1px; }
td.res .detail { margin-left:8px; color:var(--muted); font-size:.875rem; white-space:normal; }
tr[data-state="open"] .state { color:var(--open-ink); font-weight:600; }
tr[data-state="filtered"] .state { color:var(--amber-ink); }
tr[data-state="error"] .state { color:var(--red-ink); }
tr[data-state="pending"] .state, tr[data-state="skipped"] .state { color:var(--muted); }
tr[data-state="closed"] .led { background:var(--muted); opacity:.55; }
.time { text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); }
#rows.only-open tr:not([data-state="open"]) { display:none; }
.none-open { margin:4px 0 0; color:var(--muted); }
[hidden] { display:none !important; }

.explain { margin-top:28px; max-width:72ch; }
.explain summary { cursor:pointer; font-weight:500; width:max-content; }
.explain dl { display:grid; grid-template-columns:max-content 1fr; gap:8px 18px; margin:14px 0 0; }
.explain dt { font-weight:600; }
.explain dd { margin:0; color:var(--muted); }

@media (max-width:760px) {
  .wrap { padding-top:28px; }
  .controls { grid-template-columns:1fr 1fr; }
  .host, .ports, .hint, .presets { grid-column:1 / -1; }
  .host { order:1; } .ports { order:2; } .hint { order:3; } .timeout { order:4; } .run { order:5; } .presets { order:6; }
  .hint { margin-top:-4px; }
  .plate { padding:14px 16px 20px; }
  .plate::before, .plate::after { display:none; }
  .toggle { flex-basis:100%; }
  .explain dl { grid-template-columns:1fr; gap:2px; }
  .explain dd { margin-bottom:8px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation:none !important; transition:none !important; }
}
</style>
</head>
<body>
<main class="wrap">
  <header class="intro">
    <h1>Port checker</h1>
    <p>See which TCP ports on a host accept connections. Only check machines you own or have permission to test.</p>
  </header>

  <form id="form" class="controls" novalidate>
    <div class="field host">
      <label for="host">Host</label>
      <input id="host" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="127.0.0.1 or myserver.local">
    </div>
    <div class="field ports">
      <label for="ports">Ports</label>
      <input id="ports" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="22, 80, 443, 8000-8010" aria-describedby="ports-hint">
    </div>
    <div class="field timeout">
      <label for="timeout">Timeout (seconds)</label>
      <input id="timeout" type="number" min="0.1" max="10" step="0.1" inputmode="decimal">
    </div>
    <button id="run" class="run" type="submit">Check ports</button>
    <p id="ports-hint" class="hint">Separate with commas. Ranges like 8000-8010 and names like ssh work too. Up to __MAX_PORTS__ ports per check.</p>
    <div class="presets" role="group" aria-labelledby="presets-label">
      <span id="presets-label">Presets</span>
      <button type="button" data-ports="21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080">Common</button>
      <button type="button" data-ports="80, 443, 3000, 5000, 8000, 8080, 8443, 8888">Web</button>
      <button type="button" data-ports="1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017">Databases</button>
      <button type="button" data-ports="25, 110, 143, 465, 587, 993, 995">Mail</button>
      <button type="button" data-ports="22, 23, 3389, 5900, 5985, 5986">Remote access</button>
      <button type="button" data-ports="1-1024">Ports 1 to 1024</button>
    </div>
  </form>

  <p id="error" class="error" role="alert" hidden></p>

  <section id="plate" class="plate" aria-label="Port status panel">
    <div class="plate-head"><span id="plate-host">Ready</span><span id="plate-count"></span></div>
    <div id="jacks" class="jacks"><p class="plate-empty">Enter a host and ports, then choose Check ports.</p></div>
    <div class="progress" aria-hidden="true"><span id="progress"></span></div>
  </section>

  <div id="tally" class="tally idle">
    <span class="t" data-state="open"><i class="led"></i>Open <b id="n-open">0</b></span>
    <span class="t" data-state="closed"><i class="led"></i>Closed <b id="n-closed">0</b></span>
    <span class="t" data-state="filtered"><i class="led"></i>No response <b id="n-filtered">0</b></span>
    <span class="t" data-state="error"><i class="led"></i>Unreachable <b id="n-error">0</b></span>
  </div>

  <section id="results" class="results" hidden>
    <div class="results-bar">
      <p id="summary" class="summary" aria-live="polite"></p>
      <div class="actions">
        <label class="toggle"><input type="checkbox" id="only-open">Show open ports only</label>
        <button type="button" id="copy" class="ghost">Copy results</button>
        <button type="button" id="csv" class="ghost">Download CSV</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th scope="col">Port</th><th scope="col">Service</th><th scope="col">Result</th><th scope="col" class="time">Time</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <p id="none-open" class="none-open" hidden></p>
  </section>

  <details class="explain">
    <summary>What the results mean</summary>
    <dl>
      <dt>Open</dt><dd>The connection was accepted, so a service is listening on that port.</dd>
      <dt>Closed</dt><dd>The host refused the connection. It&rsquo;s reachable, but nothing is listening there.</dd>
      <dt>No response</dt><dd>Nothing answered before the timeout. Usually a firewall is dropping the traffic or the host is offline. A longer timeout rules out a slow network. On Windows, closed ports can take about two seconds to refuse, so they may show here with a short timeout.</dd>
      <dt>Unreachable</dt><dd>The network reported an error, such as no route to the host.</dd>
    </dl>
  </details>
</main>

<script>
// Everything is wrapped in one function so these names don't leak into the page's globals.
(() => {
  // $('#id'): shorthand for finding one element on the page.
  const $ = (s) => document.querySelector(s);
  const form = $('#form'), hostEl = $('#host'), portsEl = $('#ports'), timeoutEl = $('#timeout'), runBtn = $('#run');
  const errorEl = $('#error'), plate = $('#plate'), jacksEl = $('#jacks'), plateHost = $('#plate-host'), plateCount = $('#plate-count'), bar = $('#progress');
  const tally = $('#tally'), resultsEl = $('#results'), rowsEl = $('#rows'), summaryEl = $('#summary'), onlyOpen = $('#only-open'), noneOpen = $('#none-open');
  const copyBtn = $('#copy'), csvBtn = $('#csv'), tableWrap = $('.table-wrap');
  const LABEL = { pending: 'Checking', open: 'Open', closed: 'Closed', filtered: 'No response', error: 'Unreachable', skipped: 'Not checked' };
  const DENSE_AT = 96, FILTER_AT = 50;

  let controller = null;   // AbortController while a check is running
  let run = null;          // the current or last check

  // store.get / store.set: remember the last host, ports and timeout between visits.
  // Wrapped in try/catch because some browsers block storage (e.g. private windows).
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
  };
  hostEl.value = store.get('portchecker.host', '127.0.0.1');
  portsEl.value = store.get('portchecker.ports', '22, 80, 443, 3306');
  timeoutEl.value = store.get('portchecker.timeout', '1');

  // el('td', 'port', '22'): create an element with an optional class and text.
  // Text is set with textContent, so host names are never interpreted as HTML.
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  // fmtMs(0.42) -> "0.4 ms": format a response time for the table.
  const fmtMs = (ms) => (ms < 0.05 ? '<0.1' : ms < 10 ? ms.toFixed(1) : Math.round(ms).toLocaleString()) + ' ms';
  // fmtSecs(1.234) -> "1.2 s": format the total time of a check.
  const fmtSecs = (s) => (s < 0.05 ? '<0.1' : s < 10 ? s.toFixed(1) : Math.round(s)) + ' s';
  // hasTime(item): whether a response time is worth showing. A timed-out port has none.
  const hasTime = (i) => i.ms != null && (i.state === 'open' || i.state === 'closed' || i.state === 'error');
  // plural(3, 'port') -> "3 ports"
  const plural = (n, word) => n.toLocaleString() + ' ' + word + (n === 1 ? '' : 's');

  // Preset buttons: fill the Ports box with that button's list.
  document.querySelectorAll('.presets button').forEach((b) =>
    b.addEventListener('click', () => { portsEl.value = b.dataset.ports; portsEl.focus(); }));

  // The main button (or Enter in any box) starts a check, or stops the one running.
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (controller) controller.abort(); else check();
  });
  // "Show open ports only" checkbox: re-filter the table when it changes.
  onlyOpen.addEventListener('change', applyFilter);

  // Show a message in the red error box under the form.
  function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }

  // Switch the page between "check running" and "idle": the main button becomes
  // Stop while running, and Copy / Download CSV are disabled until the check ends.
  function setRunning(on) {
    runBtn.textContent = on ? 'Stop' : 'Check ports';
    runBtn.classList.toggle('stop', on);
    copyBtn.disabled = csvBtn.disabled = on;
    plate.classList.toggle('complete', !on);
  }

  // Start a check: validate the boxes, remember them, send them to the Python
  // server, then hand the streamed reply to readStream(). Shows the server's error
  // message if it rejects the input, and always tidies up with finish() at the end.
  async function check() {
    errorEl.hidden = true;
    const host = hostEl.value.trim();
    if (!host) { showError('Enter a host name or IP address.'); hostEl.focus(); return; }
    if (!portsEl.value.trim()) { showError('Enter at least one port, such as 22 or 8000-8010.'); portsEl.focus(); return; }
    store.set('portchecker.host', host);
    store.set('portchecker.ports', portsEl.value);
    store.set('portchecker.timeout', timeoutEl.value);

    controller = new AbortController();
    setRunning(true);
    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, ports: portsEl.value, timeout: timeoutEl.value || 1 }),
        signal: controller.signal,
      });
      if (!res.ok) {
        let msg = 'The check failed (HTTP ' + res.status + ').';
        try { msg = (await res.json()).error || msg; } catch (e) {}
        showError(msg);
      } else {
        await readStream(res.body);
      }
    } catch (err) {
      if (err.name !== 'AbortError') showError('Lost contact with the port checker. Make sure the Python script is still running, then try again.');
    } finally {
      controller = null;
      finish();
    }
  }

  // Read the server's reply piece by piece as it arrives. The reply is one JSON
  // object per line; each complete line is passed to handle() right away, which is
  // what makes results appear live instead of all at the end.
  async function readStream(body) {
    const reader = body.getReader(), dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) handle(JSON.parse(line));
      }
    }
  }

  // Route one message from the server: "start" sets up the display, "result"
  // updates one port, "done" records that the check finished normally.
  function handle(ev) {
    if (ev.type === 'start') begin(ev);
    else if (ev.type === 'result' && run) update(ev);
    else if (ev.type === 'done' && run) { run.elapsed = ev.elapsed; run.complete = true; }
  }

  // Set up a new check: clear the old results, then create one socket on the panel
  // and one table row for every port, all marked "Checking". Over 96 ports the panel
  // switches to compact squares, and over 50 the table shows open ports only.
  function begin(ev) {
    run = { host: ev.host, ip: ev.ip, items: new Map(), total: ev.ports.length, done: 0,
            counts: { open: 0, closed: 0, filtered: 0, error: 0 }, elapsed: null, complete: false, t0: performance.now() };
    plateHost.textContent = ev.ip && ev.ip !== ev.host ? ev.host + '  (' + ev.ip + ')' : ev.host;
    plate.classList.toggle('dense', run.total > DENSE_AT);
    jacksEl.replaceChildren();
    rowsEl.replaceChildren();
    const jf = document.createDocumentFragment(), rf = document.createDocumentFragment();
    for (const { port, service } of ev.ports) {
      const item = { port, service, state: 'pending', ms: null, detail: '' };
      item.jack = el('div', 'jack');
      item.jack.append(el('span', 'num', String(port)), el('span', 'led'), el('span', 'socket'));
      item.row = el('tr');
      const res = el('td', 'res');
      item.stateEl = el('span', 'state');
      item.detailEl = el('span', 'detail');
      res.append(el('i', 'led'), item.stateEl, item.detailEl);
      item.timeEl = el('td', 'time');
      item.row.append(el('td', 'port', String(port)), el('td', 'svc', service), res, item.timeEl);
      paint(item);
      run.items.set(port, item);
      jf.append(item.jack);
      rf.append(item.row);
    }
    jacksEl.append(jf);
    rowsEl.append(rf);
    onlyOpen.checked = run.total > FILTER_AT;
    resultsEl.hidden = false;
    tally.classList.remove('idle');
    summaryEl.textContent = 'Checking ' + plural(run.total, 'port') + ' on ' + run.host + '…';
    renderProgress();
    renderCounts();
    applyFilter();
  }

  // Redraw one port's socket and table row to match its current state
  // (light colour, label, error detail, response time, hover tooltip).
  function paint(item) {
    const label = LABEL[item.state];
    item.jack.dataset.state = item.row.dataset.state = item.state;
    item.jack.title = 'Port ' + item.port + (item.service ? ' (' + item.service + ')' : '') + ': ' + label;
    item.stateEl.textContent = label;
    item.detailEl.textContent = item.detail || '';
    item.timeEl.textContent = hasTime(item) ? fmtMs(item.ms) : '';
  }

  // Apply one port's result from the server: store it, redraw that port,
  // and bump the progress bar and the open/closed/no-response counts.
  function update(ev) {
    const item = run.items.get(ev.port);
    if (!item || item.state !== 'pending') return;
    item.state = ev.state; item.ms = ev.ms; item.detail = ev.detail;
    paint(item);
    run.done++;
    if (item.state in run.counts) run.counts[item.state]++;
    renderProgress();
    renderCounts();
    if (item.state === 'open' || onlyOpen.checked) applyFilter();
  }

  // Update the thin progress bar and the "N of M checked" label on the panel.
  function renderProgress() {
    bar.style.width = (run.total ? (run.done / run.total) * 100 : 0) + '%';
    plateCount.textContent = run.done.toLocaleString() + ' of ' + run.total.toLocaleString() + ' checked';
  }

  // Update the totals next to Open, Closed, No response and Unreachable.
  function renderCounts() {
    for (const k of Object.keys(run.counts)) $('#n-' + k).textContent = run.counts[k].toLocaleString();
  }

  // Hide non-open rows when "Show open ports only" is ticked. If that leaves the
  // table empty, hide it and show a "No open ports found" note instead.
  function applyFilter() {
    rowsEl.classList.toggle('only-open', onlyOpen.checked);
    const show = !!run && onlyOpen.checked && run.counts.open === 0;
    noneOpen.hidden = !show;
    tableWrap.hidden = show;
    if (show) noneOpen.textContent = controller
      ? 'No open ports found so far.'
      : 'No open ports found. Turn off “Show open ports only” to see every result.';
  }

  // Wrap up when a check ends for any reason (finished, stopped, or failed).
  // Ports that never got a result are marked "Not checked", and the summary
  // line says how many ports were checked and how long it took.
  function finish() {
    setRunning(false);
    if (!run) return;
    if (!run.complete) {
      for (const item of run.items.values()) if (item.state === 'pending') { item.state = 'skipped'; paint(item); }
      summaryEl.textContent = 'Stopped after checking ' + run.done.toLocaleString() + ' of ' + plural(run.total, 'port') + ' on ' + run.host + '.';
    } else {
      summaryEl.textContent = 'Checked ' + plural(run.total, 'port') + ' on ' + run.host + ' in ' + fmtSecs(run.elapsed) + '.';
    }
    applyFilter();
  }

  // "Copy results": copy the results as aligned plain text (respecting the
  // open-only filter), ready to paste into a chat or a ticket.
  copyBtn.addEventListener('click', async () => {
    if (!run) return;
    const lines = [...run.items.values()]
      .filter((i) => !onlyOpen.checked || i.state === 'open')
      .map((i) => [String(i.port).padEnd(7), (i.service || '').padEnd(15), LABEL[i.state].padEnd(13), hasTime(i) ? fmtMs(i.ms) : ''].join('').trimEnd());
    const text = 'Host: ' + run.host + (run.ip !== run.host ? ' (' + run.ip + ')' : '') + '\n' + lines.join('\n');
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = 'Copied';
      setTimeout(() => { copyBtn.textContent = 'Copy results'; }, 1600);
    } catch (e) {
      showError("Couldn't copy to the clipboard. Use Download CSV instead.");
    }
  });

  // Make one value safe for a CSV cell: quote it if it contains commas, quotes or
  // line breaks, and prefix ' if it starts with = + - @ so spreadsheet apps
  // don't run it as a formula.
  const csvCell = (v) => {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  // "Download CSV": build a CSV of every port in the last check (all rows, not just
  // the visible ones) and save it as ports-<host>.csv.
  csvBtn.addEventListener('click', () => {
    if (!run) return;
    const rows = [['host', 'ip', 'port', 'service', 'result', 'time_ms', 'detail']];
    for (const i of run.items.values())
      rows.push([run.host, run.ip, i.port, i.service, LABEL[i.state], hasTime(i) ? i.ms.toFixed(1) : '', i.detail]);
    const blob = new Blob([rows.map((r) => r.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'ports-' + run.host.replace(/[^\w.-]+/g, '_') + '.csv';
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
})();
</script>
</body>
</html>
""".replace("__MAX_PORTS__", f"{MAX_PORTS:,}")


if __name__ == "__main__":
    main()
