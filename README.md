# Proxy Relay - local proxy conversion for browser automation

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Tests](https://github.com/huazz233/proxy_relay/actions/workflows/tests.yml/badge.svg)](https://github.com/huazz233/proxy_relay/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/proxy-relay.svg)](https://pypi.org/project/proxy-relay/)

**English** | [简体中文](README_zh.md)

Proxy Relay turns authenticated upstream HTTP/HTTPS/SOCKS5/SOCKS5H proxies into local unauthenticated HTTP or SOCKS5 proxies.

This is useful when browser automation tools such as Playwright, Selenium, or DrissionPage need a local proxy URL but your upstream proxy requires credentials or a different protocol.

<img width="563" height="315" alt="proxy relay protocol conversion" src="https://github.com/user-attachments/assets/b3aa1a3d-8173-4ab0-bb25-ae31e87de549" />

## Features

- Protocol conversion between upstream HTTP/HTTPS/SOCKS5/SOCKS5H and local HTTP/SOCKS5
- Sync and async Python interfaces
- Local proxy binds to `127.0.0.1` and requires no local authentication
- Automatic cleanup on process exit, with explicit cleanup for long-running processes
- Zero runtime dependencies
- Local test coverage for the protocol matrix and key relay behavior

## Installation

```bash
pip install proxy-relay
```

For the `requests` based Quick Start below:

```bash
pip install "proxy-relay[requests]"
```

For browser/example dependencies on Python 3.8+:

```bash
pip install "proxy-relay[examples]"
```

The `examples_*.py` scripts live in this repository. Clone the repo before running those files directly.

## Quick Start

Set your real upstream proxy first. Do not include the local proxy created by this package here.

```bash
export UPSTREAM_PROXY="socks5://user:pass@proxy.example:1080"
```

```python
import os
import requests

from proxy_relay import cleanup, create_proxy

upstream = os.environ["UPSTREAM_PROXY"]
local_url = create_proxy(upstream, local_type="http")

try:
    resp = requests.get(
        "https://api.ipify.org/",
        proxies={"http": local_url, "https": local_url},
        timeout=30,
    )
    print(resp.text)
finally:
    cleanup()
```

Expected result: the printed IP should be the upstream proxy exit IP, not your direct IP.

## Common Integrations

### Playwright

```python
import asyncio
import os

from playwright.async_api import async_playwright
from proxy_relay import create_proxy_async

UPSTREAM_PROXY = os.environ["UPSTREAM_PROXY"]

async def main():
    local_url = await create_proxy_async(UPSTREAM_PROXY, local_type="http")

    async with async_playwright() as p:
        browser = await p.chromium.launch(proxy={"server": local_url}, headless=False)
        page = await browser.new_page()
        await page.goto("https://api.ipify.org/")
        print(await page.text_content("body"))
        await browser.close()

asyncio.run(main())
```

### Selenium

```python
import os

from proxy_relay import create_proxy
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

local_url = create_proxy(os.environ["UPSTREAM_PROXY"], local_type="http")

options = Options()
options.add_argument(f"--proxy-server={local_url}")

driver = webdriver.Chrome(options=options)
try:
    driver.get("https://api.ipify.org/")
    print(driver.page_source)
finally:
    driver.quit()
```

More complete examples are in [docs/integration-examples.md](docs/integration-examples.md).

## Interface

### Sync

```python
create_proxy(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0, timeout=30.0)
create_http_proxy(upstream_url, ...)
create_socks5_proxy(upstream_url, ...)
cleanup()
```

### Async

```python
await create_proxy_async(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0)
await create_http_proxy_async(upstream_url, ...)
await create_socks5_proxy_async(upstream_url, ...)
```

Context managers are available when you want explicit lifetime control:

```python
from proxy_relay import HttpProxy, Socks5Proxy

async with HttpProxy(upstream_url) as proxy:
    local_http_url = proxy.get_local_url()

async with Socks5Proxy(upstream_url) as proxy:
    local_socks5_url = proxy.get_local_url()
```

For multiple proxies:

```python
from proxy_relay import ProxyManager

async with ProxyManager() as manager:
    url = await manager.create(upstream_url, local_type="http")
    await manager.stop(url)
```

## Supported Protocols

| Upstream | Local | Example |
| --- | --- | --- |
| HTTP | HTTP / SOCKS5 | `http://proxy.example:8080` |
| HTTPS | HTTP / SOCKS5 | `https://proxy.example:8443` |
| SOCKS5 | HTTP / SOCKS5 | `socks5://user:pass@proxy.example:1080` |
| SOCKS5H | HTTP / SOCKS5 | `socks5h://user:pass@proxy.example:1080` |

Notes:

- `https://` upstream proxies are contacted over TLS.
- `socks5h://` sends domain names to the upstream SOCKS5 proxy for remote DNS resolution.
- The local proxy listens on `127.0.0.1` with an ephemeral port.

## Testing

```bash
pip install -e ".[test]"
python -m pytest -q
```

The test suite uses local fake upstream proxies and target servers. It does not require external network access or real proxy credentials.

## Multi-process / Multi-thread

- Sync helpers use a background asyncio loop and a guarded registry.
- Each process owns its own local proxy runtime.
- On Linux `fork` mode, create proxies after forking.

## Troubleshooting

- `UPSTREAM_PROXY` is missing: set it to the real upstream proxy, for example `socks5://user:pass@host:1080`.
- Browser launches but traffic is direct: pass the returned local URL to the browser proxy setting, not the upstream URL.
- `502 Bad Gateway`: the local proxy could not connect through the upstream proxy to the requested target.
- Long-running processes: use `ProxyManager` or call `cleanup()` when a proxy is no longer needed.

## License

MIT License
