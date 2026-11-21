#!/usr/bin/env python3
"""ssh ProxyCommand helper: HTTP CONNECT through the VM's egress proxy.

Reads the proxy URL (with credentials) from the https_proxy/HTTPS_PROXY
environment variable only — never prints it. Usage:
  proxy_connect.py HOST PORT
Exits non-zero if the proxy refuses the CONNECT.
"""
import base64
import os
import select
import socket
import sys
from urllib.parse import urlparse

host, port = sys.argv[1], int(sys.argv[2])
proxy_url = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
p = urlparse(proxy_url)
if not p.hostname:
    sys.stderr.write("proxy_connect: no https_proxy in env\n")
    sys.exit(1)

auth = ""
if p.username:
    creds = "%s:%s" % (p.username, p.password or "")
    auth = "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(creds.encode()).decode()

s = socket.create_connection((p.hostname, p.port or 3128), timeout=15)
s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n" % (host, port, host, port, auth)).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        sys.stderr.write("proxy_connect: proxy closed connection\n")
        sys.exit(1)
    buf += chunk
head, rest = buf.split(b"\r\n\r\n", 1)
status = head.split(b"\r\n")[0]
if b" 200 " not in status:
    sys.stderr.write("proxy_connect: CONNECT refused: %s\n" % status.decode(errors="replace"))
    sys.exit(1)

# Splice: forward the pre-read bytes, then pump both directions.
s.sendall(rest) if False else None  # rest belongs to the tunneled stream, not to us
# NOTE: `rest` is the first bytes of the server's reply (e.g. SSH banner) —
# it must go to stdout (ssh reads it from the ProxyCommand's stdout).
out = sys.stdout.buffer
inp = sys.stdin.buffer
if rest:
    out.write(rest)
    out.flush()
s.setblocking(False)
rlist = [s, sys.stdin]
while True:
    r, _, _ = select.select(rlist, [], [], 60)
    if not r:
        sys.stderr.write("proxy_connect: idle timeout\n")
        sys.exit(1)
    if s in r:
        data = s.recv(65536)
        if not data:
            break
        out.write(data)
        out.flush()
    if sys.stdin in r:
        data = inp.read1(65536) if hasattr(inp, "read1") else inp.read(65536)
        if not data:
            break
        s.sendall(data)
sys.exit(0)
