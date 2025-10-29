#!/usr/bin/env python3
import requests
from proxy_relay import create_proxy, HttpProxy, Socks5Proxy


def main():
    # 基本用法
    upstream = "socks5://user:pass@proxy.example.com:1080"
    local_url = create_proxy(upstream, 'http')
    print(f"代理启动: {local_url}")

    # 使用代理发送请求
    proxies = {'http': local_url, 'https': local_url}
    try:
        resp = requests.get('https://api.ipify.org/', proxies=proxies, timeout=10)
        print(f"当前IP: {resp.text.strip()}")
    except Exception as e:
        print(f"请求失败: {e}")

    # 上下文管理器 - 自动管理生命周期
    with HttpProxy(upstream) as proxy:
        print(f"临时代理: {proxy.get_local_url()}")
        # 代理会在退出 with 块时自动停止

    # SOCKS5 本地代理
    with Socks5Proxy(upstream) as proxy:
        print(f"SOCKS5代理: {proxy.get_local_url()}")

    # 支持的协议组合
    print("\n支持的协议组合:")
    combinations = [
        ("http://proxy.com:8080", "http", "HTTP → HTTP"),
        ("http://proxy.com:8080", "socks5", "HTTP → SOCKS5"),
        ("https://proxy.com:8080", "http", "HTTPS → HTTP"),
        ("https://proxy.com:8080", "socks5", "HTTPS → SOCKS5"),
        ("socks5://proxy.com:1080", "http", "SOCKS5 → HTTP"),
        ("socks5://proxy.com:1080", "socks5", "SOCKS5 → SOCKS5"),
        ("socks5h://proxy.com:1080", "http", "SOCKS5H → HTTP"),
        ("socks5h://proxy.com:1080", "socks5", "SOCKS5H → SOCKS5"),
    ]

    for upstream, local_type, desc in combinations:
        try:
            url = create_proxy(upstream, local_type)
            print(f"{desc}: {url}")
        except Exception as e:
            print(f"{desc}: 失败 - {e}")

    # 错误处理
    print("\n错误处理:")
    try:
        create_proxy("invalid://url", "http")
    except ValueError as e:
        print(f"配置错误: {e}")

    try:
        create_proxy("ftp://proxy.com:21", "http")
    except ValueError as e:
        print(f"协议错误: {e}")


if __name__ == "__main__":
    main()
