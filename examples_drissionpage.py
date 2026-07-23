import os

from proxy_relay import create_proxy
from DrissionPage import ChromiumPage, ChromiumOptions

UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY")
TEST_URL = "https://api.ipify.org/"

if not UPSTREAM_PROXY:
    raise SystemExit("Set UPSTREAM_PROXY, for example: socks5://user:pass@proxy.example:1080")


def main() -> None:
    """Use DrissionPage with a local proxy created by proxy_relay."""
    # Convert upstream proxy to a local HTTP proxy
    local_url = create_proxy(UPSTREAM_PROXY, local_type="http")

    options = ChromiumOptions()
    # DrissionPage accepts full proxy URL, e.g. http://127.0.0.1:12345
    options.set_proxy(local_url)

    page = ChromiumPage(options)
    try:
        page.get(TEST_URL)
        print(page.html)
    finally:
        page.quit()


if __name__ == "__main__":
    main()
