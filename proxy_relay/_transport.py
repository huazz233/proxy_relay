"""Transport primitives shared by proxy adapters."""

import asyncio
import contextlib
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from ._errors import UpstreamConnectionError

# StreamReader limit is a flow-control watermark (pause at 2*limit), NOT a
# line-length guard. Line length is enforced separately in protocol readers.
STREAM_LIMIT = 256 * 1024
RELAY_CHUNK_SIZE = 64 * 1024
WRITE_BUFFER_HIGH = 512 * 1024
WRITE_BUFFER_LOW = 128 * 1024
DEFAULT_CLOSE_TIMEOUT = 1.0
DNS_CACHE_TTL = 60.0

_dns_cache: Dict[Tuple[str, int], Tuple[str, float]] = {}


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        sock.listen(1)
        return sock.getsockname()[1]


@dataclass
class UpstreamTunnel:
    """An established byte stream to either an upstream proxy or a target tunnel."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    async def close(self, timeout: Optional[float] = DEFAULT_CLOSE_TIMEOUT) -> None:
        await close_writer(self.writer, timeout=timeout)


def close_writer_now(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is not None and not writer.is_closing():
        writer.close()


async def close_writer(writer: Optional[asyncio.StreamWriter],
                       timeout: Optional[float] = DEFAULT_CLOSE_TIMEOUT) -> None:
    """Close a StreamWriter without allowing Windows transports to stall shutdown."""
    if writer is None:
        return

    close_writer_now(writer)

    with contextlib.suppress(Exception):
        if timeout is None:
            await writer.wait_closed()
        else:
            await asyncio.wait_for(writer.wait_closed(), timeout=timeout)


def configure_socket(writer: asyncio.StreamWriter) -> None:
    """Apply keepalive (and rely on asyncio's default TCP_NODELAY)."""
    sock = writer.get_extra_info('socket')
    if sock is None:
        return
    with contextlib.suppress(OSError, AttributeError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    transport = writer.transport
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.set_write_buffer_limits(high=WRITE_BUFFER_HIGH, low=WRITE_BUFFER_LOW)


async def resolve_host(host: str, port: int) -> str:
    """Resolve *host* once and cache for DNS_CACHE_TTL seconds.

    IPs and already-cached names short-circuit. Failures fall through to
    the original host so open_connection can surface its own error.
    """
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except (OSError, ValueError):
        pass

    key = (host, port)
    now = time.monotonic()
    cached = _dns_cache.get(key)
    if cached is not None and cached[1] > now:
        return cached[0]

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM,
        )
    except OSError:
        return host

    if not infos:
        return host

    resolved = infos[0][4][0]
    _dns_cache[key] = (resolved, now + DNS_CACHE_TTL)
    return resolved


async def connect_upstream(host: str, port: int, timeout: Optional[float] = None, *,
                           use_tls: bool = False, server_hostname: Optional[str] = None,
                           ssl_context: Optional[ssl.SSLContext] = None):
    try:
        connect_host = await resolve_host(host, port)
        kwargs = {"limit": STREAM_LIMIT}
        if use_tls:
            kwargs["ssl"] = ssl_context or ssl.create_default_context()
            kwargs["server_hostname"] = server_hostname or host
        if timeout is not None:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port, **kwargs),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.open_connection(connect_host, port, **kwargs)
        configure_socket(writer)
        return reader, writer
    except asyncio.TimeoutError:
        raise UpstreamConnectionError(f"Connection timeout {host}:{port}")
    except UpstreamConnectionError:
        raise
    except Exception as exc:
        os_errno = getattr(exc, 'errno', None)
        if os_errno is None and isinstance(exc.__cause__, OSError):
            os_errno = exc.__cause__.errno
        raise UpstreamConnectionError(
            f"Connection failed {host}:{port} - {exc}",
            os_errno=os_errno,
        ) from exc
