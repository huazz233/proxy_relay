# Proxy Relay - 面向浏览器自动化的本地代理转换器

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Tests](https://github.com/huazz233/proxy_relay/actions/workflows/tests.yml/badge.svg)](https://github.com/huazz233/proxy_relay/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/proxy-relay.svg)](https://pypi.org/project/proxy-relay/)

[English](README.md) | **简体中文**

Proxy Relay 可以把带认证的上游 HTTP/HTTPS/SOCKS5/SOCKS5H 代理转换成本地无认证 HTTP 或 SOCKS5 代理。

典型场景：Playwright、Selenium、DrissionPage 等浏览器自动化工具需要一个本地代理 URL，但你的上游代理有账号密码，或者协议不是目标工具最方便使用的协议。

<img width="563" height="315" alt="proxy relay protocol conversion" src="https://github.com/user-attachments/assets/cef89b23-726b-4395-af8a-2dcdd80ee4a7" />

## 特性

- 支持上游 HTTP/HTTPS/SOCKS5/SOCKS5H 到本地 HTTP/SOCKS5 的协议转换
- 同步和异步 Python interface
- 本地代理监听 `127.0.0.1`，本地侧不需要账号密码
- 进程退出自动清理，也支持长期进程手动清理
- 零运行时依赖
- 使用本地 fake upstream 覆盖协议矩阵和关键转发行为

## 安装

```bash
pip install proxy-relay
```

如果要运行下面基于 `requests` 的 Quick Start：

```bash
pip install "proxy-relay[requests]"
```

如果要在 Python 3.8+ 上安装浏览器示例依赖：

```bash
pip install "proxy-relay[examples]"
```

`examples_*.py` 脚本位于本仓库内。要直接运行这些文件，请先 clone 仓库。

## Quick Start

先设置真实上游代理。这里不要填本库创建出来的本地代理 URL。

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

预期结果：打印出的 IP 应该是上游代理出口 IP，而不是你的直连 IP。

## 常见集成

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

更多完整示例见 [docs/integration-examples.md](docs/integration-examples.md)。

## Interface

### 同步

```python
create_proxy(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0, timeout=30.0)
create_http_proxy(upstream_url, ...)
create_socks5_proxy(upstream_url, ...)
cleanup()
```

### 异步

```python
await create_proxy_async(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0)
await create_http_proxy_async(upstream_url, ...)
await create_socks5_proxy_async(upstream_url, ...)
```

需要显式控制生命周期时，可以使用上下文管理器：

```python
from proxy_relay import HttpProxy, Socks5Proxy

async with HttpProxy(upstream_url) as proxy:
    local_http_url = proxy.get_local_url()

async with Socks5Proxy(upstream_url) as proxy:
    local_socks5_url = proxy.get_local_url()
```

管理多个代理：

```python
from proxy_relay import ProxyManager

async with ProxyManager() as manager:
    url = await manager.create(upstream_url, local_type="http")
    await manager.stop(url)
```

## 支持协议

| 上游协议 | 本地协议 | 示例 |
| --- | --- | --- |
| HTTP | HTTP / SOCKS5 | `http://proxy.example:8080` |
| HTTPS | HTTP / SOCKS5 | `https://proxy.example:8443` |
| SOCKS5 | HTTP / SOCKS5 | `socks5://user:pass@proxy.example:1080` |
| SOCKS5H | HTTP / SOCKS5 | `socks5h://user:pass@proxy.example:1080` |

说明：

- `https://` 上游代理会通过 TLS 连接。
- `socks5h://` 会把域名交给上游 SOCKS5 代理解析。
- 本地代理监听 `127.0.0.1` 和随机空闲端口。

## 测试

```bash
pip install -e ".[test]"
python -m pytest -q
```

测试使用本地 fake upstream proxy 和 target server，不需要外网，也不需要真实代理账号。

## 多进程 / 多线程

- 同步 helper 使用后台 asyncio loop 和带锁 registry。
- 每个进程拥有自己的本地代理 runtime。
- Linux `fork` 模式建议在 fork 后创建代理。

## 排查

- 缺少 `UPSTREAM_PROXY`：设置真实上游代理，例如 `socks5://user:pass@host:1080`。
- 浏览器流量还是直连：确认传给浏览器的是本库返回的本地 URL，而不是上游 URL。
- `502 Bad Gateway`：本地代理无法通过上游代理连接目标地址。
- 长期运行进程：使用 `ProxyManager` 或在不需要代理时调用 `cleanup()`。

## 许可证

MIT License
