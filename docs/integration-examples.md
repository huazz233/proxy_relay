# Integration Examples

These examples assume you already have a real upstream proxy.

The `examples_*.py` files referenced below are repository scripts. Clone this repository if you want to run them directly after installing the optional dependencies.

Set it once:

```bash
export UPSTREAM_PROXY="socks5://user:pass@proxy.example:1080"
```

On Windows PowerShell:

```powershell
$env:UPSTREAM_PROXY = "socks5://user:pass@proxy.example:1080"
```

## Requests

Install:

```bash
pip install "proxy-relay[requests]"
```

Run:

```python
import os
import requests

from proxy_relay import cleanup, create_proxy

local_url = create_proxy(os.environ["UPSTREAM_PROXY"], local_type="http")

try:
    response = requests.get(
        "https://api.ipify.org/",
        proxies={"http": local_url, "https": local_url},
        timeout=30,
    )
    print(response.text)
finally:
    cleanup()
```

Expected output: the upstream proxy exit IP.

## Playwright

Requires Python 3.8+.

Install:

```bash
pip install "proxy-relay[examples]"
playwright install chromium
```

Run:

```bash
git clone https://github.com/huazz233/proxy_relay.git
cd proxy_relay
python examples_playwright.py
```

The script creates a local HTTP proxy and passes that local URL to Chromium.

## Selenium

Requires Python 3.8+.

Install:

```bash
pip install "proxy-relay[examples]"
```

Run:

```bash
git clone https://github.com/huazz233/proxy_relay.git
cd proxy_relay
python examples_selenium.py
```

Make sure ChromeDriver is available for your local Chrome installation.

## DrissionPage

Requires Python 3.8+.

Install:

```bash
pip install "proxy-relay[examples]"
```

Run:

```bash
git clone https://github.com/huazz233/proxy_relay.git
cd proxy_relay
python examples_drissionpage.py
```

## Protocol Matrix Smoke Script

`examples.py` tries HTTP, HTTPS, SOCKS5, and SOCKS5H upstream forms against local HTTP and SOCKS5 proxies.

It expects the upstream proxy address without a scheme:

```bash
git clone https://github.com/huazz233/proxy_relay.git
cd proxy_relay
export UPSTREAM_PROXY_ADDR="user:pass@proxy.example:1080"
python examples.py
```

Use this only if the same upstream host supports all schemes you want to test. Many commercial providers expose different ports for HTTP and SOCKS5.

## Troubleshooting

- `Set UPSTREAM_PROXY`: the example refuses to run with fake credentials.
- Direct IP is printed: check that the client is using the returned local URL.
- `502 Bad Gateway`: the upstream proxy rejected the target or could not connect to it.
- Browser opens but no page loads: try `local_type="http"` first; browser proxy support is more consistent for local HTTP proxies.
