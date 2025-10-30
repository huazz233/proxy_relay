# Proxy Relay - 代理中转器

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

代理协议转换工具,支持 HTTP/HTTPS/SOCKS5/SOCKS5H 互转。

**主要应用场景**: Playwright/Selenium 等自动化工具的代理中转

## 特性

- 协议互转: 支持 8 种协议组合
- 同步/异步API: 适配不同使用场景
- 自动清理: 进程退出时自动释放资源
- 线程安全: 支持多线程/多进程并发
- 零依赖: 纯Python实现

## 安装

```bash
pip install git+https://github.com/huazz233/proxy_relay.git
```

## 快速开始

```python
from proxy_relay import create_proxy
import requests

# 创建本地代理
url = create_proxy("socks5://user:pass@proxy.com:1080")

# 使用代理
resp = requests.get("https://api.ipify.org/", proxies={'http': url, 'https': url})
print(resp.text)
```

## 使用场景

### 脚本/测试

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
    # 简单方式
    url = await create_proxy_async("http://proxy.com:8080")

    # 上下文管理器
    async with HttpProxy("http://proxy.com:8080") as proxy:
        url = proxy.get_local_url()
        # 使用代理...

asyncio.run(main())
```

### Playwright集成

```python
import asyncio
from proxy_relay import create_proxy_async
from playwright.async_api import async_playwright

async def main():
    url = await create_proxy_async("socks5://user:pass@proxy.com:1080")

    async with async_playwright() as p:
        browser = await p.chromium.launch(proxy={"server": url})
        page = await browser.new_page()
        await page.goto('https://api.ipify.org/')
        await browser.close()

asyncio.run(main())
```



## API参考

### 同步API

```python
# 创建代理
create_proxy(upstream_url, local_type='http', connect_timeout=30.0, idle_timeout=300.0, timeout=30.0)
create_http_proxy(upstream_url, ...)      # 快捷方法
create_socks5_proxy(upstream_url, ...)    # 快捷方法

# 清理代理 (可选,进程退出时自动清理)
cleanup()
```

### 异步API

```python
# 创建代理
await create_proxy_async(upstream_url, local_type='http', ...)
await create_http_proxy_async(upstream_url, ...)
await create_socks5_proxy_async(upstream_url, ...)

# 上下文管理器
async with HttpProxy(upstream_url) as proxy:
    url = proxy.get_local_url()

async with Socks5Proxy(upstream_url) as proxy:
    url = proxy.get_local_url()
```

### 高级API

```python
# ProxyManager - 管理多个代理
with ProxyManager() as manager:
    url = manager.create(upstream_url, local_type='http')
    manager.stop(url)      # 停止单个
    manager.stop_all()     # 停止所有
```

## 支持的协议

| 上游协议 | 本地协议 | 示例 |
|---------|---------|------|
| HTTP/HTTPS | HTTP/SOCKS5 | `http://proxy.com:8080` |
| SOCKS5 | HTTP/SOCKS5 | `socks5://user:pass@proxy.com:1080` |
| SOCKS5H | HTTP/SOCKS5 | `socks5h://proxy.com:1080` |

## 参数说明

- `upstream_url`: 上游代理URL
- `local_type`: 本地代理类型 (`'http'` 或 `'socks5'`)
- `connect_timeout`: 连接超时(秒),默认30
- `idle_timeout`: 空闲超时(秒),默认300
- `timeout`: 创建超时(秒),默认30

## 多进程/多线程

- 完全线程安全
- 多进程安全 (Windows/macOS默认spawn模式)
- Linux fork模式: 建议在fork前不要创建代理

## 常见问题

**Q: 代理会一直运行吗?**
A: 会,直到进程结束或手动调用 `cleanup()`

**Q: 长期运行的服务如何避免资源累积?**
A: 定期调用 `cleanup()` 或使用 `ProxyManager`

**Q: 同步API和异步API有什么区别?**
A: 同步API适合脚本,异步API适合异步应用(如FastAPI)

## 许可证

MIT License
