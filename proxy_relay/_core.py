"""Local proxy server orchestration (async core)."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse

from ._errors import ClientConnectionError, ProxyError, UpstreamConnectionError
from ._protocol import (
    SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_CMD_CONNECT,
    SOCKS5_COMMAND_NOT_SUPPORTED,
    SOCKS5_GENERAL_FAILURE,
    SOCKS5_NO_AUTH,
    SOCKS5_NO_ACCEPTABLE_METHODS,
    SOCKS5_SUCCESS,
    SOCKS5_VERSION,
    build_basic_proxy_auth,
    is_socks_scheme,
    map_connect_error_to_socks5_rep,
    parse_host_port as _parse_host_port,
    parse_proxy_url,
    read_exact as _read_exact,
    read_http_request,
    read_socks5_address,
    send_socks5_reply,
)
from ._transport import STREAM_LIMIT, UpstreamTunnel, configure_socket
from ._tunnel import TunnelRuntime
from ._upstream import HttpUpstreamConnector, create_upstream_connector

__version__ = "1.4.0"
__author__ = "huazz233"

logger = logging.getLogger(__name__)


class BaseProxy(ABC):
    def __init__(self, upstream_url: str, connect_timeout: Optional[float] = 30.0,
                 idle_timeout: Optional[float] = 300.0):
        self.upstream_config = parse_proxy_url(upstream_url)
        self.local_port = 0
        self.local_host = '127.0.0.1'
        self.running = False
        self._server = None
        self._start_lock: Optional[asyncio.Lock] = None
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self._runtime = TunnelRuntime(idle_timeout, logger=logger)
        self.upstream_connector = create_upstream_connector(
            self.upstream_config,
            connect_timeout,
            track_writer=self._runtime.track_writer,
            untrack_writer=self._runtime.untrack_writer,
        )

    def _get_start_lock(self) -> asyncio.Lock:
        # Lazily create so BaseProxy can be constructed outside a running loop
        # on Python 3.8/3.9.
        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        return self._start_lock

    async def start(self) -> str:
        async with self._get_start_lock():
            if self.running:
                return self.get_local_url()

            self._runtime.reopen()
            server = await asyncio.start_server(
                self._run_client,
                self.local_host,
                0,
                limit=STREAM_LIMIT,
            )
            if not server.sockets:
                server.close()
                await server.wait_closed()
                raise ProxyError("Local proxy server did not expose a bound socket")

            self._server = server
            self.local_port = server.sockets[0].getsockname()[1]
            self.running = True
            logger.info("%s started on %s", self.__class__.__name__, self.get_local_url())
            return self.get_local_url()

    async def stop(self):
        was_running = self.running
        self.running = False
        server = self._server
        self._server = None
        if server:
            server.close()
        await self._runtime.close_all()
        if server:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=self._runtime.close_timeout)
            except asyncio.TimeoutError:
                logger.debug("Timed out waiting for local server socket to close")
        if was_running:
            logger.info("%s stopped", self.__class__.__name__)

    @abstractmethod
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        pass

    async def _run_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        configure_socket(writer)
        task = asyncio.current_task()
        self._runtime.track_task(task)
        try:
            await self._handle_client(reader, writer)
        finally:
            self._runtime.untrack_task(task)

    @abstractmethod
    def get_local_url(self) -> str:
        pass

    def _track_tunnel(self, tunnel: UpstreamTunnel) -> UpstreamTunnel:
        # Connector already tracks the writer on open; keep this as a no-op
        # identity helper so call sites stay readable.
        return tunnel

    async def _connect_upstream(self, target_host: str, target_port: int) -> UpstreamTunnel:
        return self._track_tunnel(await self.upstream_connector.connect(target_host, target_port))

    async def _relay_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                          upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter):
        await self._runtime.relay(client_reader, client_writer, upstream_reader, upstream_writer)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        await self.stop()
        return False

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.get_local_url()})"

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}("
                f"upstream={self.upstream_config['scheme']}://{self.upstream_config['host']}:{self.upstream_config['port']}, "
                f"local={self.get_local_url()}, "
                f"running={self.running})")


def _write_http_response(writer: asyncio.StreamWriter, status: bytes,
                         extra_headers: bytes = b"") -> None:
    writer.write(b"HTTP/1.1 " + status + b"\r\n" + extra_headers + b"\r\n")


async def _drain_http_response(writer: asyncio.StreamWriter, status: bytes,
                               timeout: Optional[float] = None,
                               extra_headers: bytes = b"") -> None:
    _write_http_response(writer, status, extra_headers=extra_headers)
    if timeout is not None:
        await asyncio.wait_for(writer.drain(), timeout=timeout)
    else:
        await writer.drain()


async def _try_respond(writer: asyncio.StreamWriter, status: bytes,
                       timeout: Optional[float] = None) -> None:
    try:
        await _drain_http_response(writer, status, timeout=timeout)
    except Exception as exc:
        logger.debug("Failed to send HTTP %s: %r", status.decode(errors='replace'), exc)


def _force_connection_close(headers: list) -> list:
    """Strip Connection headers and force Connection: close."""
    filtered = [
        h for h in headers
        if not h.lower().startswith(b'connection:')
        and not h.lower().startswith(b'proxy-connection:')
    ]
    filtered.append(b'Connection: close\r\n')
    return filtered


class HttpProxy(BaseProxy):
    def get_local_url(self) -> str:
        return f"http://{self.local_host}:{self.local_port}"

    async def _open_http_upstream(self) -> UpstreamTunnel:
        if not isinstance(self.upstream_connector, HttpUpstreamConnector):
            raise ProxyError("HTTP forwarding requires an HTTP upstream connector")
        return self._track_tunnel(await self.upstream_connector.open_proxy_stream())

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._runtime.track_writer(writer)
        try:
            request = await read_http_request(reader, self.connect_timeout)
            if request is None:
                return

            if request.is_connect:
                await self._handle_connect(reader, writer, request)
            else:
                await self._handle_http_request(reader, writer, request)

        except ClientConnectionError as exc:
            logger.debug("Client error: %s", exc)
            await _try_respond(writer, b"400 Bad Request", timeout=self.connect_timeout)
        except Exception as exc:
            logger.warning("Unhandled error in HTTP client handler: %r", exc, exc_info=True)
            await _try_respond(writer, b"500 Internal Server Error", timeout=self.connect_timeout)
        finally:
            await self._runtime.close_one(writer)

    async def _handle_connect(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              request) -> None:
        tunnel = None
        try:
            target_host, target_port = _parse_host_port(request.target)
            tunnel = await self._connect_upstream(target_host, target_port)

            await _drain_http_response(writer, b"200 Connection Established",
                                       timeout=self.connect_timeout)
            await self._relay_data(reader, writer, tunnel.reader, tunnel.writer)

        except ClientConnectionError as exc:
            logger.debug("CONNECT client error: %s", exc)
            await _try_respond(writer, b"400 Bad Request", timeout=self.connect_timeout)
        except Exception as exc:
            logger.warning("CONNECT upstream error: %r", exc)
            await _try_respond(writer, b"502 Bad Gateway", timeout=self.connect_timeout)
        finally:
            if tunnel is not None:
                await self._runtime.close_one(tunnel.writer)

    async def _handle_http_request(self, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter,
                                   request) -> None:
        try:
            if is_socks_scheme(self.upstream_config['scheme']):
                await self._handle_http_via_socks5(reader, writer, request)
            else:
                await self._handle_http_via_http(reader, writer, request)
        except ClientConnectionError as exc:
            logger.debug("HTTP request client error: %s", exc)
            await _try_respond(writer, b"400 Bad Request", timeout=self.connect_timeout)
        except Exception as exc:
            logger.warning("HTTP request upstream error: %r", exc)
            await _try_respond(writer, b"502 Bad Gateway", timeout=self.connect_timeout)

    async def _handle_http_via_socks5(self, reader: asyncio.StreamReader,
                                      writer: asyncio.StreamWriter,
                                      request) -> None:
        tunnel = None
        try:
            method, url, version = request.method, request.target, request.version
            parsed = urlparse(url)
            if not parsed.hostname:
                raise ClientConnectionError(f"HTTP proxy request must use absolute-form URL: {url}")
            if parsed.scheme.lower() == 'https':
                raise ClientConnectionError("HTTPS proxy requests must use CONNECT")

            target_host = parsed.hostname
            target_port = parsed.port or 80
            path = parsed.path or '/'
            if parsed.params:
                path += ';' + parsed.params
            if parsed.query:
                path += '?' + parsed.query

            tunnel = await self._connect_upstream(target_host, target_port)
            # Force Connection: close so keep-alive cannot mis-route subsequent
            # requests through a tunnel bound to the first Host.
            headers = _force_connection_close([
                h for h in request.headers if not h.lower().startswith(b'proxy-')
            ])
            tunnel.writer.write(f"{method} {path} {version}\r\n".encode())
            for header in headers:
                tunnel.writer.write(header)
            tunnel.writer.write(b'\r\n')
            await tunnel.writer.drain()

            await self._relay_data(reader, writer, tunnel.reader, tunnel.writer)
        finally:
            if tunnel is not None:
                await self._runtime.close_one(tunnel.writer)

    async def _handle_http_via_http(self, reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter,
                                    request) -> None:
        tunnel = None
        try:
            tunnel = await self._open_http_upstream()
            # Force Connection: close so we never leave a keep-alive connection
            # that would skip auth rewrite on the next request.
            headers = _force_connection_close([
                h for h in request.headers
                if not h.lower().startswith(b'proxy-authorization:')
            ])

            tunnel.writer.write(request.raw_line)
            for header in headers:
                tunnel.writer.write(header)

            if self.upstream_config.get('username') and self.upstream_config.get('password'):
                tunnel.writer.write(build_basic_proxy_auth(self.upstream_config))
            tunnel.writer.write(b'\r\n')
            await tunnel.writer.drain()

            await self._relay_data(reader, writer, tunnel.reader, tunnel.writer)
        finally:
            if tunnel is not None:
                await self._runtime.close_one(tunnel.writer)


class Socks5Proxy(BaseProxy):
    """SOCKS5 proxy supporting both HTTP CONNECT and SOCKS5 clients."""

    def get_local_url(self) -> str:
        return f"socks5://{self.local_host}:{self.local_port}"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._runtime.track_writer(writer)
        try:
            initial_data = await _read_exact(reader, 1, self.connect_timeout)

            if initial_data and initial_data[0] == SOCKS5_VERSION:
                await self._handle_socks5(reader, writer)
            else:
                await self._handle_http(reader, writer, initial_data)

        except ClientConnectionError as exc:
            logger.debug("SOCKS5/HTTP client error: %s", exc)
        except Exception as exc:
            logger.warning("Unhandled error in SOCKS5 client handler: %r", exc, exc_info=True)
        finally:
            await self._runtime.close_one(writer)

    async def _handle_socks5(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            nmethods = (await _read_exact(reader, 1, self.connect_timeout))[0]
            methods = await _read_exact(reader, nmethods, self.connect_timeout)
            if SOCKS5_NO_AUTH not in methods:
                writer.write(bytes([SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_METHODS]))
                await asyncio.wait_for(writer.drain(), timeout=self.connect_timeout)
                return

            writer.write(bytes([SOCKS5_VERSION, SOCKS5_NO_AUTH]))
            await asyncio.wait_for(writer.drain(), timeout=self.connect_timeout)

            ver, cmd, _reserved, atyp = await _read_exact(reader, 4, self.connect_timeout)
            if ver != SOCKS5_VERSION or cmd != SOCKS5_CMD_CONNECT:
                await send_socks5_reply(writer, SOCKS5_COMMAND_NOT_SUPPORTED,
                                        timeout=self.connect_timeout)
                return

            try:
                target_host, target_port, _addr_type = await read_socks5_address(
                    reader, atyp, self.connect_timeout,
                )
            except ClientConnectionError:
                await send_socks5_reply(writer, SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
                                        timeout=self.connect_timeout)
                return

            try:
                tunnel = await self._connect_upstream(target_host, target_port)
            except Exception as exc:
                logger.warning("SOCKS5 upstream connect failed %s:%s: %r",
                               target_host, target_port, exc)
                await send_socks5_reply(writer, map_connect_error_to_socks5_rep(exc),
                                        timeout=self.connect_timeout)
                return

            try:
                await send_socks5_reply(writer, SOCKS5_SUCCESS, timeout=self.connect_timeout)
                await self._relay_data(reader, writer, tunnel.reader, tunnel.writer)
            finally:
                await self._runtime.close_one(tunnel.writer)

        except Exception as exc:
            logger.debug("SOCKS5 handshake error: %r", exc)
            try:
                await send_socks5_reply(writer, SOCKS5_GENERAL_FAILURE,
                                        timeout=self.connect_timeout)
            except Exception as send_exc:
                logger.debug("Failed to send SOCKS5 failure reply: %r", send_exc)

    async def _handle_http(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter,
                           initial_data: bytes):
        tunnel = None
        try:
            request = await read_http_request(reader, self.connect_timeout, initial_data=initial_data)
            if request is None:
                return
            if not request.is_connect:
                await _drain_http_response(writer, b"400 Bad Request",
                                           timeout=self.connect_timeout)
                return

            target_host, target_port = _parse_host_port(request.target)
            tunnel = await self._connect_upstream(target_host, target_port)

            await _drain_http_response(writer, b"200 Connection Established",
                                       timeout=self.connect_timeout)
            await self._relay_data(reader, writer, tunnel.reader, tunnel.writer)

        except ClientConnectionError as exc:
            logger.debug("HTTP-on-SOCKS5 client error: %s", exc)
            await _try_respond(writer, b"400 Bad Request", timeout=self.connect_timeout)
        except Exception as exc:
            logger.warning("HTTP-on-SOCKS5 upstream error: %r", exc)
            await _try_respond(writer, b"502 Bad Gateway", timeout=self.connect_timeout)
        finally:
            if tunnel is not None:
                await self._runtime.close_one(tunnel.writer)


def _create_proxy_instance(upstream_url: str, local_type: str,
                           connect_timeout: float,
                           idle_timeout: float):
    if not upstream_url:
        raise ValueError("Upstream proxy URL must not be empty")

    if local_type not in ['http', 'socks5']:
        raise ValueError(f"Unsupported local proxy type: {local_type}")

    if local_type == 'http':
        return HttpProxy(upstream_url, connect_timeout=connect_timeout, idle_timeout=idle_timeout)
    return Socks5Proxy(upstream_url, connect_timeout=connect_timeout, idle_timeout=idle_timeout)


class ProxyManager:
    def __init__(self):
        self._proxies = {}

    async def create(self, upstream_url: str, local_type: str = 'http',
                     connect_timeout: float = 30.0, idle_timeout: float = 300.0) -> str:
        proxy = _create_proxy_instance(upstream_url, local_type, connect_timeout, idle_timeout)
        local_url = await proxy.start()
        self._proxies[local_url] = proxy
        return local_url

    async def stop(self, local_url: str):
        proxy = self._proxies.pop(local_url, None)
        if proxy:
            await proxy.stop()

    async def stop_all(self):
        proxies = list(self._proxies.values())
        self._proxies.clear()
        results = await asyncio.gather(
            *(proxy.stop() for proxy in proxies),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                logger.warning("Error stopping proxy: %r", result)

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        await self.stop_all()
        return False

    def __repr__(self):
        return f"ProxyManager(active_proxies={len(self._proxies)})"


async def create_proxy_async(upstream_url: str, local_type: str = 'http',
                             connect_timeout: float = 30.0,
                             idle_timeout: float = 300.0) -> str:
    """Create and start a local proxy on the *current* event loop.

    The returned proxy is registered so :func:`stop_proxy_async` /
    :func:`cleanup` can stop it. Prefer :class:`ProxyManager` or
    ``async with HttpProxy(...)`` when you want explicit ownership.
    """
    from ._sync import register_proxy

    proxy = _create_proxy_instance(upstream_url, local_type, connect_timeout, idle_timeout)
    local_url = await proxy.start()
    register_proxy(local_url, proxy, loop=asyncio.get_running_loop())
    return local_url


async def create_http_proxy_async(upstream_url: str, connect_timeout: float = 30.0,
                                  idle_timeout: float = 300.0) -> str:
    return await create_proxy_async(upstream_url, 'http',
                                    connect_timeout=connect_timeout, idle_timeout=idle_timeout)


async def create_socks5_proxy_async(upstream_url: str, connect_timeout: float = 30.0,
                                    idle_timeout: float = 300.0) -> str:
    return await create_proxy_async(upstream_url, 'socks5',
                                    connect_timeout=connect_timeout, idle_timeout=idle_timeout)


async def stop_proxy_async(local_url: str) -> None:
    """Stop a proxy previously created via :func:`create_proxy_async`."""
    from ._sync import unregister_and_stop_async
    await unregister_and_stop_async(local_url)
