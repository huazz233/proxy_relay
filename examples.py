#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests

from proxy_relay import create_proxy

PROXY_ADDR = "user:pass@proxy.example.com:1080"
# TEST_URL = "http://208.95.112.1/json/"
TEST_URL = "https://api.ipify.org/"
TIMEOUT = 30


def get_direct_ip():
    try:
        return requests.get(TEST_URL, timeout=TIMEOUT).text.strip()
    except:
        return None


def test_proxy(local_url):
    try:
        proxies = {'http': local_url, 'https': local_url}
        return requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT).text.strip()
    except:
        return None


def main():
    combinations = [
        ("http", "http", "HTTP->HTTP"),
        ("http", "socks5", "HTTP->SOCKS5"),
        ("https", "http", "HTTPS->HTTP"),
        ("https", "socks5", "HTTPS->SOCKS5"),
        ("socks5", "http", "SOCKS5->HTTP"),
        ("socks5", "socks5", "SOCKS5->SOCKS5"),
        ("socks5h", "http", "SOCKS5H->HTTP"),
        ("socks5h", "socks5", "SOCKS5H->SOCKS5"),
    ]

    direct_ip = get_direct_ip()
    print(f"本机IP: {direct_ip}\n")

    results = []
    for i, (upstream_proto, local_proto, desc) in enumerate(combinations, 1):
        upstream_url = f"{upstream_proto}://{PROXY_ADDR}"

        try:
            local_url = create_proxy(upstream_url, local_proto)
            proxy_ip = test_proxy(local_url)

            if proxy_ip:
                status = "OK" if proxy_ip != direct_ip else "WARN"
                print(f"[{i}/8] {desc:20} {status:4} {proxy_ip}")
                results.append((desc, True, proxy_ip))
            else:
                print(f"[{i}/8] {desc:20} FAIL")
                results.append((desc, False, None))
        except Exception as e:
            print(f"[{i}/8] {desc:20} ERR  {str(e)[:40]}")
            results.append((desc, False, None))

    success = sum(1 for _, ok, _ in results if ok)
    print(f"\n成功率: {success}/{len(combinations)}")


if __name__ == "__main__":
    main()
