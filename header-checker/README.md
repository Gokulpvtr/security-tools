# Security Header Checker

Checks whether a website sends common security headers and flags information-leaking headers.

## Install
```bash
pip install -r requirements.txt
```

## Usage
```bash
python3 header_checker.py https://example.com
```

## Checks
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Leaky headers: Server, X-Powered-By, X-AspNet-Version

Use only on sites you own or are allowed to test.
