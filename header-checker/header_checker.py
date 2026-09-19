#!/usr/bin/env python3
"""Security header checker. Use only on sites you own or are allowed to test."""
import argparse
import sys

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS (HSTS)",
    "Content-Security-Policy": "Limits script/content sources (XSS mitigation)",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "Stops MIME sniffing (should be 'nosniff')",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
}
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def check(url: str, timeout: int = 10) -> int:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}")
        return 1

    print(f"[*] {r.url} ({r.status_code})\n")
    missing = 0
    for header, why in SECURITY_HEADERS.items():
        value = r.headers.get(header)
        if value:
            print(f"[+] {header}: {value}")
        else:
            print(f"[-] MISSING {header}: {why}")
            missing += 1

    print()
    for header in LEAKY_HEADERS:
        if header in r.headers:
            print(f"[!] Information leak: {header}: {r.headers[header]}")

    print(f"\nMissing {missing} of {len(SECURITY_HEADERS)} security headers.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Check HTTP security headers.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    sys.exit(check(args.url, args.timeout))


if __name__ == "__main__":
    main()
