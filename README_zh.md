# Proxy Relay - 代理中转器

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/proxy-relay.svg)](https://pypi.org/project/proxy-relay/)

> 本文档为简体中文版本。English version: [README.md](README.md)

代理协议转换工具，支持 HTTP/HTTPS/SOCKS5/SOCKS5H 互转，本地代理无需账密认证。

**主要应用场景**：Playwright / Selenium / DrissionPage 等自动化工具的代理中转。

## 特性

- 协议互转：支持 8 种协议组合
- 同步 / 异步 API：适配不同使用场景
- 自动清理：进程退出时自动释放资源
- 线程安全：支持多线程 / 多进程并发
- 零依赖：纯 Python 实现

## 安装

```bash
pip install proxy-relay
```

如果希望安装最新 GitHub 版本，可以使用：

```bash
pip install "git+https://github.com/huazz233/proxy_relay.git"
```

## 快速开始

```python
from proxy_relay import create_proxy
import requests

# 创建本地代理（从上游 SOCKS5 代理转换为本地 HTTP 代理）
url = create_proxy("socks5://user:pass@proxy.com:1080")

# 使用本地代理访问测试地址
resp = requests.get("https://api.ipify.org/", proxies={"http": url, "https": url})
print(resp.text)
```

## 使用场景

### 脚本 / 测试

```python
from proxy_relay import create_proxy

url = create_proxy("http://proxy.com:8080")
# 使用代理...
# 进程退出时自动清理
```

### 长期运行服务

```python
from proxy_relay import create_proxy, cleanup

url = create_proxy("http://proxy.com:8080")
# 使用代理...
cleanup()  # 手动清理
```

### 异步应用

```python
import asyncio
from proxy_relay import create_proxy_async, HttpProxy

async def main():
    # 简单方式：直接创建本地代理 URL
    url = await create_proxy_async("http://proxy.com:8080")

    # 上下文管理器方式：自动启动和关闭代理
    async with HttpProxy("http://proxy.com:8080") as proxy:
        url = proxy.get_local_url()
        # 使用代理...

asyncio.run(main())
```

### Playwright 集成（Python）

```python
import asyncio
from proxy_relay import create_proxy_async
from playwright.async_api import ProxySettings, async_playwright

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

async def main():
    # 通过 proxy_relay 将上游代理转换成本地 HTTP 代理
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

### Selenium 集成（Python）

```python
from proxy_relay import create_proxy
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

def main():
    # 创建本地 HTTP 代理
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

### DrissionPage 集成（Python）

```python
from proxy_relay import create_proxy
from DrissionPage import ChromiumPage, ChromiumOptions

UPSTREAM_PROXY = "socks5://user:pass@proxy.com:1080"
TEST_URL = "https://api.ipify.org/"

def main():
    # 创建本地 HTTP 代理
    local_url = create_proxy(UPSTREAM_PROXY, local_type="http")

    options = ChromiumOptions()
    # 直接使用本地代理 URL
    options.set_proxy(local_url)

    page = ChromiumPage(options)
    page.get(TEST_URL)
    print(page.html)
    page.quit()

if __name__ == "__main__":
    main()
```

> 更多集成示例与运行说明，可参考：`docs/integration-examples.md`。

## API 参考

### 同步 API

```python
# 创建代理
create_proxy(upstream_url, local_type="http", connect_timeout=30.0, idle_timeout=300.0, timeout=30.0)
create_http_proxy(upstream_url, ...)      # HTTP 代理快捷方法
create_socks5_proxy(upstream_url, ...)    # SOCKS5 代理快捷方法

# 清理代理（可选，进程退出时自动清理）
cleanup()
```

### 异步 API

```python
# 创建代理
await create_proxy_async(upstream_url, local_type="http", ...)
await create_http_proxy_async(upstream_url, ...)
await create_socks5_proxy_async(upstream_url, ...)

# 上下文管理器
async with HttpProxy(upstream_url) as proxy:
    url = proxy.get_local_url()

async with Socks5Proxy(upstream_url) as proxy:
    url = proxy.get_local_url()
```

### 高级 API

```python
# ProxyManager - 管理多个代理
import asyncio
from proxy_relay import ProxyManager

async def main():
    async with ProxyManager() as manager:
        url = await manager.create(upstream_url, local_type="http")
        await manager.stop(url)      # 停止单个
        await manager.stop_all()     # 停止所有

asyncio.run(main())
```

## 支持的协议

| 上游协议   | 本地协议     | 示例                             |
|------------|--------------|----------------------------------|
| HTTP/HTTPS | HTTP/SOCKS5  | `http://proxy.com:8080`          |
| SOCKS5     | HTTP/SOCKS5  | `socks5://user:pass@proxy.com:1080` |
| SOCKS5H    | HTTP/SOCKS5  | `socks5h://proxy.com:1080`       |

## 参数说明

- `upstream_url`：上游代理 URL
- `local_type`：本地代理类型（`"http"` 或 `"socks5"`）
- `connect_timeout`：连接超时（秒），默认 30
- `idle_timeout`：空闲超时（秒），默认 300
- `timeout`：创建超时（秒），默认 30

## 多进程 / 多线程

- 完全线程安全
- 多进程安全（Windows / macOS 默认 spawn 模式）
- Linux fork 模式：建议在 fork 前不要创建代理

## 常见问题

**Q: 代理会一直运行吗？**  
A: 会，直到进程结束或手动调用 `cleanup()`。

**Q: 长期运行的服务如何避免资源累积？**  
A: 定期调用 `cleanup()` 或使用 `ProxyManager`。

**Q: 同步 API 和异步 API 有什么区别？**  
A: 同步 API 适合脚本，异步 API 适合异步应用（如 FastAPI）。

## 许可证

MIT License
