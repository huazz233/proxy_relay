"""Public interface for proxy_relay."""

from ._core import (
    BaseProxy,
    HttpProxy,
    ProxyManager,
    Socks5Proxy,
    __author__,
    __version__,
    create_http_proxy_async,
    create_proxy_async,
    create_socks5_proxy_async,
    stop_proxy_async,
)
from ._errors import ClientConnectionError, ProxyError, UpstreamConnectionError
from ._protocol import (
    MAX_DOMAIN_LEN,
    MAX_LINE_SIZE,
    extract_sni_from_client_hello,
    is_socks_scheme,
    parse_proxy_url,
    send_http_connect,
    send_socks5_connect,
)
from ._sync import (
    cleanup,
    create_http_proxy,
    create_proxy,
    create_socks5_proxy,
    stop_proxy,
)
from ._transport import connect_upstream, find_free_port

__all__ = [
    "create_proxy",
    "create_http_proxy",
    "create_socks5_proxy",
    "create_proxy_async",
    "create_http_proxy_async",
    "create_socks5_proxy_async",
    "stop_proxy",
    "stop_proxy_async",
    "cleanup",
    "HttpProxy",
    "Socks5Proxy",
    "BaseProxy",
    "ProxyManager",
    "ProxyError",
    "UpstreamConnectionError",
    "ClientConnectionError",
    "connect_upstream",
    "send_http_connect",
    "send_socks5_connect",
    "parse_proxy_url",
    "is_socks_scheme",
    "extract_sni_from_client_hello",
    "find_free_port",
    "MAX_LINE_SIZE",
    "MAX_DOMAIN_LEN",
    "__version__",
    "__author__",
]
