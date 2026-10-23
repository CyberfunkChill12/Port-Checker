# Port Checker

A small web app for checking which TCP ports on a host accept connections. You run one
Python file, it opens a page in your browser, and results appear as each port is checked.

> **Only check hosts you own or have permission to test.** Scanning other people's
> machines without permission may break their acceptable-use policies or the law.

## Requirements

- Python 3.8 or newer
- A modern browser (Chrome, Edge, Firefox or Safari)

The app uses only Python's standard library, so there's nothing to install.

## Quick start

```bash
python3 port_checker.py
```

On Windows, use `py port_checker.py` instead.

The terminal shows the address (normally `http://127.0.0.1:8765`) and your browser opens
it automatically. To stop the app, press **Ctrl+C** in the terminal.

### Command-line options

| Option | What it does |
| --- | --- |
| `--port 9000` | Serve the page on a different port. The default is 8765. If the port is busy, the next 9 are tried in turn. |
| `--no-browser` | Don't open a browser tab. Visit the printed address yourself. |

## Using the page

1. **Host.** Enter a host name or IP address, such as `127.0.0.1`, `myserver.local` or
   `192.168.1.20`.
   - You can paste a full URL (`https://example.com/page`) and only the host is used.
   - For IPv6, use either `::1` or `[::1]`.
   - Don't add a port to the host (`example.com:8080`). Put ports in the Ports box.
2. **Ports.** List the ports to check, separated by commas, spaces or semicolons.
   - Single ports: `22, 80, 443`
   - Ranges: `8000-8010`
   - Service names: `ssh, https, postgres`
   - Mixed: `ssh, 80, 443, 8000-8010`
   - The preset buttons (Common, Web, Databases, Mail, Remote access, Ports 1 to 1024)
     fill the box for you.
3. **Timeout.** How many seconds to wait for each port before giving up, from 0.1 to 10.
   One second suits most networks. Use a longer timeout for slow or distant hosts.
4. Choose **Check ports**. While a check runs the button changes to **Stop**, which
   cancels the remaining ports.

The page remembers your last host, ports and timeout the next time you open it.

### Reading the results

The panel shows a socket for each port, and its light changes colour as each result
arrives. Hover over a socket to see its port and result. Checks of more than 96 ports
show compact squares instead of sockets so the panel stays a manageable size.

| Result | Light | Meaning |
| --- | --- | --- |
| **Open** | Green | The connection was accepted, so a service is listening on that port. |
| **Closed** | Off | The host refused the connection. It's reachable, but nothing is listening there. |
| **No response** | Amber | Nothing answered before the timeout. Usually a firewall is dropping the traffic, or the host is offline. |
| **Unreachable** | Red | The network reported an error, such as no route to the host. The error is shown next to the result. |
| **Not checked** | Faded | The check was stopped before this port was tried. |

The table lists every port with its usual service name, its result and how long the
connection attempt took. Below the panel, totals for each result update as the check runs.

- **Show open ports only** hides everything else in the table. It's switched on
  automatically when you check more than 50 ports.
- **Copy results** copies the table as plain text, ready to paste into a chat or ticket.
  It respects the open-only filter.
- **Download CSV** saves every port from the last check as `ports-<host>.csv`, with the
  columns `host, ip, port, service, result, time_ms, detail`.

## Limits

| Limit | Value | Where to change it |
| --- | --- | --- |
| Ports per check | 1,024 | `MAX_PORTS` |
| Ports checked at the same time | 100 | `MAX_WORKERS` |
| Timeout | 0.1 to 10 seconds | `MIN_TIMEOUT`, `MAX_TIMEOUT` |
| Default timeout | 1 second | `DEFAULT_TIMEOUT` |

The settings are constants near the top of `port_checker.py`. To add or rename service
names, edit the `SERVICES` table there.

Other things to know:

- **TCP only.** UDP ports can't be checked this way, because UDP has no connection to
  accept or refuse.
- **IPv4 first.** If a name resolves to both IPv4 and IPv6 addresses, the IPv4 address is
  used, as in the original script. To check over IPv6, enter the IPv6 address directly.
- **The check runs from this computer.** Results reflect what this machine can reach.
  Another network or machine may get different results, since firewalls often treat
  connections differently depending on where they come from.

## Security

The app is meant to be used only on the computer it's running on.

- The server listens on `127.0.0.1` only, so other devices on your network can't open the
  page or use it to scan through your machine.
- Requests addressed to any other host name are rejected, which blocks DNS-rebinding
  tricks.
- Requests from other websites are rejected, so a page open in another tab can't trigger
  checks.

Don't change the code to listen on `0.0.0.0` or a network address unless you understand
that anyone who can reach it could use your machine to probe other hosts.

## How it works

```
Browser page                         port_checker.py
-------------                        ---------------
Check ports  --- POST /api/check -->  validate host, ports, timeout
                                     look up the host once
                                     check up to 100 ports at a time
results      <-- one JSON line ----  ...sent as each port finishes
appear live      per event
```

1. `main()` starts a web server on `127.0.0.1` and opens the page.
2. The page sends the host, ports and timeout to `/api/check`.
3. `Handler.do_POST()` validates the input with `normalize_host`, `parse_ports`,
   `parse_timeout` and `resolve`, then runs `check_port` for each port in a thread pool.
4. Each result is written back as soon as it's ready, one JSON object per line, and the
   page's JavaScript updates the panel and table.

Every function in the file has a comment explaining what it does.

### Using the API directly

You can call the same endpoint from a script while the app is running. For example,
with `curl` on macOS or Linux:

```bash
curl -N -X POST http://127.0.0.1:8765/api/check \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1", "ports": "22, 80, 8000-8002", "timeout": 1}'
```

The reply is a stream of JSON lines:

```text
{"type": "start", "host": "127.0.0.1", "ip": "127.0.0.1", "ports": [{"port": 22, "service": "ssh"}, ...]}
{"type": "result", "port": 80, "state": "open", "ms": 0.39, "detail": ""}
{"type": "result", "port": 22, "state": "closed", "ms": 0.29, "detail": ""}
{"type": "done", "elapsed": 0.004}
```

- `state` is one of `open`, `closed`, `filtered` (shown on the page as "No response") or
  `error` (shown as "Unreachable").
- Results arrive in the order the checks finish, not in port order.
- Invalid input returns HTTP 400 with a JSON body such as
  `{"error": "70000 is outside the valid port range (1-65535)."}`.

## Troubleshooting

**The browser didn't open.**
Copy the address printed in the terminal into your browser. On a machine without a
desktop, run with `--no-browser`.

**"Couldn't start the web UI on ports 8765-8774."**
Something else is using those ports. Choose another, such as `--port 9100`.

**"Lost contact with the port checker."**
The Python script stopped, or its terminal was closed. Start it again and reload the page.

**Every port shows No response.**
A firewall is probably dropping the connections, or the host is offline. Try a longer
timeout to rule out a slow network. On Windows, closed ports can take about two seconds
to refuse a connection, so with a short timeout they may show as No response instead of
Closed.

**A service shows Closed, but I know it's running.**
It may only be listening on one address. A service bound to `::1` (IPv6) won't answer on
`127.0.0.1`, and one bound to `127.0.0.1` won't answer on your network IP. Try the other
address.

**Every port shows Open, even ones that shouldn't be.**
Something between you and the host is accepting every connection on its behalf, such as
a proxy, VPN or security software. The results describe that device, not the host.

**The font looks different from usual.**
The page loads its typeface from Google Fonts. Without internet access it uses your
system font instead, and everything else works the same.
