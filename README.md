# Proxy Relay - 代理中转器

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

多协议代理中转器，支持 HTTP/HTTPS/SOCKS5/SOCKS5H 协议互转，本地代理无需账密认证。

## 特性

- **协议互转**: 支持 8 种协议组合 (HTTP/HTTPS/SOCKS5/SOCKS5H)
- **无账密认证**: 本地代理无需配置账密，简化应用接入
- 支持上游代理账密认证
- 基于 asyncio 异步架构
- 跨平台支持 (Windows/Linux/macOS)
- 无外部依赖

## 安装

```bash
pip install git+https://github.com/huazz233/proxy_relay.git
```

开发模式：

```bash
git clone https://github.com/huazz233/proxy_relay.git
cd proxy_relay
pip install -e ".[dev]"
```

## 支持的协议组合

| 上游协议 | 本地协议 | 描述 |
|---------|---------|------|
| HTTP | HTTP | HTTP上游 → HTTP本地 |
| HTTP | SOCKS5 | HTTP上游 → SOCKS5本地 |
| HTTPS | HTTP | HTTPS上游 → HTTP本地 |
| HTTPS | SOCKS5 | HTTPS上游 → SOCKS5本地 |
| SOCKS5 | HTTP | SOCKS5上游 → HTTP本地 |
| SOCKS5 | SOCKS5 | SOCKS5上游 → SOCKS5本地 |
| SOCKS5H | HTTP | SOCKS5H上游 → HTTP本地 |
| SOCKS5H | SOCKS5 | SOCKS5H上游 → SOCKS5本地 |

## 使用

```python
from proxy_relay import create_proxy

upstream_url = "socks5://username:password@proxy.example.com:1080"
local_proxy_url = create_proxy(upstream_url, 'http')

import requests
proxies = {'http': local_proxy_url, 'https': local_proxy_url}
response = requests.get('https://api.ipify.org/', proxies=proxies)
```

上下文管理器：

```python
from proxy_relay import HttpProxy, Socks5Proxy

with HttpProxy("socks5://user:pass@proxy.com:1080") as proxy:
    local_url = proxy.get_local_url()

with Socks5Proxy("http://proxy.com:8080") as proxy:
    local_url = proxy.get_local_url()
```

其他API：

```python
from proxy_relay import create_http_proxy, create_socks5_proxy
from proxy_relay import get_supported_protocols, get_version_info

http_proxy_url = create_http_proxy("socks5://proxy.com:1080")
socks5_proxy_url = create_socks5_proxy("http://proxy.com:8080")

protocols = get_supported_protocols()
version = get_version_info()
print(f"版本: {version['version']}")
print(f"支持的上游协议: {protocols['upstream_protocols']}")
```

## 测试

```bash
python test_proxy_combinations.py
```



## API

### create_proxy(upstream_url, local_type='http')

```python
proxy_url = create_proxy("socks5://proxy.com:1080", 'http')
proxy_url = create_proxy("http://proxy.com:8080", 'socks5')
```

### create_http_proxy(upstream_url)

```python
proxy_url = create_http_proxy("socks5://proxy.com:1080")
```

### create_socks5_proxy(upstream_url)

```python
proxy_url = create_socks5_proxy("http://proxy.com:8080")
```

### HttpProxy(upstream_url)

```python
with HttpProxy("socks5://proxy.com:1080") as proxy:
    local_url = proxy.get_local_url()
```

### Socks5Proxy(upstream_url)

```python
with Socks5Proxy("http://proxy.com:8080") as proxy:
    local_url = proxy.get_local_url()
```

## 配置

超时参数：

```python
proxy_url = create_proxy("socks5://user:pass@proxy.com:1080", 'http',
                        connect_timeout=60.0, idle_timeout=None)
```

- `connect_timeout`: 连接超时，默认 30 秒
- `idle_timeout`: 空闲超时，默认 300 秒

## 调试

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 许可证

MIT License
