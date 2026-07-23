import os

from proxy_relay import create_proxy
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY")
TEST_URL = "https://api.ipify.org/"

if not UPSTREAM_PROXY:
    raise SystemExit("Set UPSTREAM_PROXY, for example: socks5://user:pass@proxy.example:1080")


def main() -> None:
    """Use Selenium (Chrome) with a local proxy created by proxy_relay."""
    # Convert upstream proxy to a local HTTP proxy that Chrome understands
    local_url = create_proxy(UPSTREAM_PROXY, local_type="http")

    options = Options()
    # Chrome accepts scheme://host:port, e.g. http://127.0.0.1:12345
    options.add_argument(f"--proxy-server={local_url}")

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(TEST_URL)
        print(driver.page_source)
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
