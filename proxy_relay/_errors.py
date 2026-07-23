"""Exception hierarchy for proxy_relay internals and public facade."""

from typing import Optional


class ProxyError(Exception):
    """Base error raised by proxy_relay."""


class UpstreamConnectionError(ProxyError):
    """The configured upstream proxy could not establish a target tunnel."""

    def __init__(
        self,
        message: str,
        *,
        socks5_rep: Optional[int] = None,
        os_errno: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.socks5_rep = socks5_rep
        self.os_errno = os_errno


class ClientConnectionError(ProxyError):
    """The local client sent an invalid or incomplete proxy request,
    or the client-side connection timed out / closed mid-handshake.
    """
