#!/usr/bin/env python3
"""Check whether the registered Cloudflare token can list Tunnels (read-only).
Reuses the custom.cloudflare connector credential via dynamic surrogate.
Usage: python3 check-tunnel-permission.py
"""
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request

PROVIDER = "custom.cloudflare"
HOST = "api.cloudflare.com"
BASE = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = "5f382a6a93aa58b9ddfa077251384fbd"


def call(method, path):
    url = BASE + path
    req = urllib.request.Request(url, method=method)
    add_surrogate_to_request(req, PROVIDER, allowed_hosts=[HOST])
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


if __name__ == "__main__":
    status, body = call("GET", f"/accounts/{ACCOUNT_ID}/cfd_tunnel")
    print("HTTP", status)
    print(body[:2000])
