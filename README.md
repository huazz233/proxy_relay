# Proxy Relay - Proxy Relay/Conversion

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/proxy-relay.svg)](https://pypi.org/project/proxy-relay/)

**English** | [简体中文](README_zh.md)

Proxy Relay is a pure-Python proxy relay/conversion tool that can convert
upstream HTTP/HTTPS/SOCKS5/SOCKS5H proxies into local HTTP or SOCKS5 proxies.
The local proxy itself does not require authentication.

**Typical use cases**: proxy relay for automation tools such as
Playwright, Selenium and DrissionPage.

## Features

- Protocol conversion: supports 8 protocol combinations
- Sync & async APIs: suitable for scripts and async apps
- Auto cleanup: resources are released on process exit
- Thread/process safe: works in multithreaded and multiprocess scenarios
- Zero runtime dependencies: implemented in pure Python

## Installation

```bash
pip install proxy-relay
```

To install the latest version from GitHub:

```bash
pip install "git+https://github.com/huazz233/proxy_relay.git"
```

## Quick Start

```python
from proxy_relay import create_proxy
import requests

# Create a local proxy from an upstream SOCKS5 proxy
url = create_proxy("socks5://user:pass@proxy.com:1080")

# Use the local proxy to access a test URL
resp = requests.get("https://api.ipify.org/", proxies={"http": url, "https": url})
print(resp.text)
```

## Use Cases

### Scripts / Tests

```python
from proxy_relay import create_proxy

url = create_proxy("http://proxy.com:8080")
# Use the proxy...
# Resources will be cleaned up automatically when the process exits
```

### Long-running Services

```python
from proxy_relay import create_proxy, cleanup

url = create_proxy("http://proxy.com:8080")
# Use the proxy...
cleanup()  # Manually cleanup in long-running services
```

### Async Applications

```python
import asyncio
from proxy_relay import create_proxy_async, HttpProxy

async def main():
    # Simple: directly create a local proxy URL
    url = await create_proxy_async("http://proxy.com:8080")

    # Context manager: automatically start and stop the proxy
    async with HttpProxy("http://proxy.com:8080") as proxy:
        url = proxy.get_local_url()
        # Use the proxy...

asyncio.run(main())
```

### Playwright Integration (Python)

```python
import asyncio
from proxy_relay import create_proxy_async
from playwright.async_api import ProxySettings, async_playwright

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

async def main():
    # Convert upstream proxy to a local HTTP proxy
    local_url = await create_proxy_async(UPSTREAM_PROXY, local_type="http")

    async with async_playwright() as p:
        proxy: ProxySettings = {"server": local_url}
        browser = await p.chromium.launch(proxy=proxy, headless=False)
        page = await browser.new_page()
        await page.goto(TEST_URL)
        print(await page.text_content("body"))
        await browser.close()

asyncio.run(main())
```

### Selenium Integration (Python)

```python
from proxy_relay import create_proxy
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

def main():
    # Create a local HTTP proxy
    local_url = create_proxy(UPSTREAM_PROXY, local_type="http")

    options = Options()
    options.add_argument(f"--proxy-server={local_url}")

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(TEST_URL)
        print(driver.page_source)
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
```

### DrissionPage Integration (Python)

```python
from proxy_relay import create_proxy
from DrissionPage import ChromiumPage, ChromiumOptions

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

def main():
    # Create a local HTTP proxy
    local_url = create_proxy(UPSTREAM_PROXY, local_type="http")

    options = ChromiumOptions()
    # DrissionPage accepts a full proxy URL, e.g. http://127.0.0.1:12345
    options.set_proxy(local_url)

    page = ChromiumPage(options)
    page.get(TEST_URL)
    print(page.html)
    page.quit()

if __name__ == "__main__":
    main()
```

> For more detailed integration examples, see `docs/integration-examples.md`.

## API Reference

### Sync APIs

```python
# Create a proxy
create_proxy(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0, timeout=30.0)
create_http_proxy(upstream_url, ...)      # Shortcut for HTTP proxies
create_socks5_proxy(upstream_url, ...)    # Shortcut for SOCKS5 proxies

# Cleanup (optional, resources are also cleaned on process exit)
cleanup()
```

### Async APIs

```python
# Create a proxy
await create_proxy_async(upstream_url, local_type="http", ...)
await create_http_proxy_async(upstream_url, ...)
await create_socks5_proxy_async(upstream_url, ...)

# Context managers
async with HttpProxy(upstream_url) as proxy:
    url = proxy.get_local_url()

async with Socks5Proxy(upstream_url) as proxy:
    url = proxy.get_local_url()
```

### Advanced APIs

```python
# ProxyManager - manage multiple proxies
import asyncio
from proxy_relay import ProxyManager

async def main():
    async with ProxyManager() as manager:
        url = await manager.create(upstream_url, local_type="http")
        await manager.stop(url)      # Stop a single proxy
        await manager.stop_all()     # Stop all proxies

asyncio.run(main())
```

## Supported Protocols

| Upstream   | Local       | Example                             |
|------------|------------|-------------------------------------|
| HTTP/HTTPS | HTTP/SOCKS5| `http://proxy.com:8080`             |
| SOCKS5     | HTTP/SOCKS5| `socks5://user:pass@proxy.com:1080` |
| SOCKS5H    | HTTP/SOCKS5| `socks5h://proxy.com:1080`          |

## Parameters

- `upstream_url`: upstream proxy URL
- `local_type`: local proxy type (`"http"` or `"socks5"`)
- `connect_timeout`: connection timeout in seconds (default 30)
- `idle_timeout`: idle timeout in seconds (default 300)
- `timeout`: creation timeout in seconds (default 30)

## Multi-process / Multi-thread

- Fully thread-safe
- Safe for multi-process use (Windows / macOS default `spawn` mode)
- On Linux `fork` mode, it is recommended **not** to create proxies before forking

## FAQ

**Q: Will the proxy keep running?**  
A: Yes, until the process exits or `cleanup()` is called.

**Q: How to avoid resource leaks in long-running services?**  
A: Call `cleanup()` periodically or use `ProxyManager` to manage proxies.

**Q: What's the difference between sync and async APIs?**  
A: Sync APIs are convenient for simple scripts; async APIs are more suitable for async applications (e.g. FastAPI).

## License

MIT License
