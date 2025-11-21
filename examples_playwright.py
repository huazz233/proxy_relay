import os
import asyncio

from proxy_relay import create_proxy_async
from playwright.async_api import ProxySettings, async_playwright

UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY", "socks5://user:pass@proxy.com:1080")
TEST_URL = "https://api.ipify.org/"
print(UPSTREAM_PROXY)

async def main() -> None:
    """Use Playwright with a local proxy created by proxy_relay."""
    # Convert upstream proxy to a local HTTP proxy
    local_url = await create_proxy_async(UPSTREAM_PROXY, local_type="http")

    async with async_playwright() as p:
        proxy: ProxySettings = {"server": local_url}
        browser = await p.chromium.launch(proxy=proxy, headless=False)
        page = await browser.new_page()
        await page.goto(TEST_URL)
        text = await page.text_content("body")
        print(text.strip() if text else "<empty>")
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
