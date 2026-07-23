import asyncio
import base64
import socket
import ssl
from urllib.parse import urlparse

import pytest

import proxy_relay
from proxy_relay import (
    HttpProxy,
    ProxyError,
    Socks5Proxy,
    UpstreamConnectionError,
    parse_proxy_url,
    stop_proxy,
)
from proxy_relay._protocol import (
    SOCKS5_CONNECTION_REFUSED,
    SOCKS5_GENERAL_FAILURE,
    SOCKS5_HOST_UNREACHABLE,
    map_connect_error_to_socks5_rep,
    send_socks5_connect,
)
from proxy_relay._transport import connect_upstream


def test_package_root_keeps_legacy_import_surface():
    names = [
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
    ]

    for name in names:
        assert hasattr(proxy_relay, name)
        assert name in proxy_relay.__all__


async def _read_headers(reader):
    headers = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=2)
        if not line or line == b"\r\n":
            return headers
        headers.append(line)


async def _close_writer(writer):
    if writer.is_closing():
        return
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                if writer.can_write_eof():
                    try:
                        writer.write_eof()
                    except Exception:
                        pass
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass


async def _relay(client_reader, client_writer, target_reader, target_writer):
    try:
        await asyncio.gather(
            _pipe(client_reader, target_writer),
            _pipe(target_reader, client_writer),
            return_exceptions=True,
        )
    finally:
        await _close_writer(client_writer)
        await _close_writer(target_writer)


async def _start_server(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _stop_server(server):
    server.close()
    await server.wait_closed()


class TargetHttpServer:
    def __init__(self):
        self.requests = []

    async def handler(self, reader, writer):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=2)
            headers = await _read_headers(reader)
            self.requests.append((request_line, headers))
            body = b"target-ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 9\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            await writer.drain()
        finally:
            await _close_writer(writer)


class HttpProxyUpstream:
    def __init__(self, fail_connect=False, connect_status=200):
        self.fail_connect = fail_connect
        self.connect_status = connect_status
        self.requests = []

    async def handler(self, reader, writer):
        target_reader = None
        target_writer = None
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=2)
            headers = await _read_headers(reader)
            self.requests.append((request_line, headers))
            parts = request_line.decode("ascii", errors="ignore").strip().split()
            if len(parts) < 3:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            method, target, version = parts
            if method.upper() == "CONNECT":
                if self.fail_connect:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await writer.drain()
                    return
                host, port_text = target.rsplit(":", 1)
                target_reader, target_writer = await asyncio.open_connection(host, int(port_text))
                writer.write(f"HTTP/1.1 {self.connect_status} Connection Established\r\n\r\n".encode("ascii"))
                await writer.drain()
                await _relay(reader, writer, target_reader, target_writer)
                return

            parsed = urlparse(target)
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            target_reader, target_writer = await asyncio.open_connection(parsed.hostname, port)
            target_writer.write(
                f"{method} {path} {version}\r\n"
                f"Host: {parsed.hostname}\r\n"
                "Connection: close\r\n"
                "\r\n"
                .encode("ascii")
            )
            await target_writer.drain()
            response = await asyncio.wait_for(target_reader.read(), timeout=2)
            writer.write(response)
            await writer.drain()
        finally:
            if target_writer is not None:
                await _close_writer(target_writer)
            await _close_writer(writer)


class Socks5ProxyUpstream:
    def __init__(self):
        self.requests = []

    async def handler(self, reader, writer):
        target_reader = None
        target_writer = None
        try:
            version, nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=2)
            assert version == 0x05
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=2)
            writer.write(b"\x05\x00")
            await writer.drain()

            version, cmd, _reserved, atyp = await asyncio.wait_for(reader.readexactly(4), timeout=2)
            assert version == 0x05
            assert cmd == 0x01
            if atyp == 0x01:
                host = socket.inet_ntoa(await asyncio.wait_for(reader.readexactly(4), timeout=2))
            elif atyp == 0x03:
                length = (await asyncio.wait_for(reader.readexactly(1), timeout=2))[0]
                host = (await asyncio.wait_for(reader.readexactly(length), timeout=2)).decode("ascii")
            else:
                raise AssertionError(f"unexpected address type {atyp}")
            port = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), timeout=2), "big")
            self.requests.append((host, port))

            target_reader, target_writer = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await _relay(reader, writer, target_reader, target_writer)
        finally:
            if target_writer is not None:
                await _close_writer(target_writer)
            await _close_writer(writer)


class CaptureSocks5Upstream:
    def __init__(self):
        self.requests = []

    async def handler(self, reader, writer):
        try:
            version, nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=2)
            assert version == 0x05
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=2)
            writer.write(b"\x05\x00")
            await writer.drain()

            version, cmd, _reserved, atyp = await asyncio.wait_for(reader.readexactly(4), timeout=2)
            assert version == 0x05
            assert cmd == 0x01
            if atyp == 0x03:
                length = (await asyncio.wait_for(reader.readexactly(1), timeout=2))[0]
                host = (await asyncio.wait_for(reader.readexactly(length), timeout=2)).decode("ascii")
            else:
                raise AssertionError(f"expected domain address type, got {atyp}")
            port = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), timeout=2), "big")
            self.requests.append((host, port))
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
        finally:
            await _close_writer(writer)


class HangingConnectUpstream:
    def __init__(self):
        self.connected = asyncio.Event()
        self.closed = asyncio.Event()

    async def handler(self, reader, writer):
        try:
            self.connected.set()
            await reader.readline()
            await _read_headers(reader)
            await reader.read()
        finally:
            await _close_writer(writer)
            self.closed.set()


class HangingConnector:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def connect(self, target_host, target_port):
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


async def _http_request_through_local_proxy(local_url, target_port):
    parsed = urlparse(local_url)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    try:
        writer.write(
            f"GET http://127.0.0.1:{target_port}/probe HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n"
            "Connection: close\r\n"
            "\r\n"
            .encode("ascii")
        )
        await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=3)
    finally:
        await _close_writer(writer)


async def _socks5_request_through_local_proxy(local_url, target_port):
    parsed = urlparse(local_url)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"\x05\x00"

        writer.write(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + int(target_port).to_bytes(2, "big")
        )
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(10), timeout=2)
        assert reply[1] == 0x00

        writer.write(
            f"GET /probe HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n"
            "Connection: close\r\n"
            "\r\n"
            .encode("ascii")
        )
        await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=3)
    finally:
        await _close_writer(writer)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("upstream_kind", "local_type"),
    [
        ("http", "http"),
        ("http", "socks5"),
        ("socks5", "http"),
        ("socks5", "socks5"),
        ("socks5h", "http"),
        ("socks5h", "socks5"),
    ],
)
async def test_protocol_matrix_with_local_upstreams(upstream_kind, local_type):
    target = TargetHttpServer()
    http_upstream = HttpProxyUpstream()
    socks_upstream = Socks5ProxyUpstream()
    target_server, target_port = await _start_server(target.handler)
    http_server, http_port = await _start_server(http_upstream.handler)
    socks_server, socks_port = await _start_server(socks_upstream.handler)
    try:
        if upstream_kind == "http":
            upstream_url = f"http://127.0.0.1:{http_port}"
        else:
            upstream_url = f"{upstream_kind}://127.0.0.1:{socks_port}"

        proxy_cls = HttpProxy if local_type == "http" else Socks5Proxy
        async with proxy_cls(upstream_url, connect_timeout=2.0, idle_timeout=2.0) as proxy:
            if local_type == "http":
                response = await _http_request_through_local_proxy(proxy.get_local_url(), target_port)
            else:
                response = await _socks5_request_through_local_proxy(proxy.get_local_url(), target_port)

        assert b"200 OK" in response
        assert b"target-ok" in response
        assert target.requests
    finally:
        await _stop_server(target_server)
        await _stop_server(http_server)
        await _stop_server(socks_server)


@pytest.mark.asyncio
async def test_local_socks5_returns_failure_when_upstream_connect_fails():
    failing_upstream = HttpProxyUpstream(fail_connect=True)
    upstream_server, upstream_port = await _start_server(failing_upstream.handler)
    try:
        async with Socks5Proxy(f"http://127.0.0.1:{upstream_port}", connect_timeout=2.0) as proxy:
            parsed = urlparse(proxy.get_local_url())
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
            try:
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"\x05\x00"
                writer.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + (9).to_bytes(2, "big"))
                await writer.drain()
                reply = await asyncio.wait_for(reader.readexactly(10), timeout=2)
                assert reply[1] != 0x00
            finally:
                await _close_writer(writer)
    finally:
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_http_forwarding_injects_configured_upstream_auth():
    target = TargetHttpServer()
    upstream = HttpProxyUpstream()
    target_server, target_port = await _start_server(target.handler)
    upstream_server, upstream_port = await _start_server(upstream.handler)
    try:
        async with HttpProxy(f"http://user:pass@127.0.0.1:{upstream_port}", connect_timeout=2.0) as proxy:
            parsed = urlparse(proxy.get_local_url())
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
            try:
                writer.write(
                    f"GET http://127.0.0.1:{target_port}/auth HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{target_port}\r\n"
                    "Proxy-Authorization: Basic wrong\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    .encode("ascii")
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), timeout=3)
            finally:
                await _close_writer(writer)

        assert b"target-ok" in response
        expected = b"Proxy-Authorization: Basic " + base64.b64encode(b"user:pass")
        upstream_headers = b"".join(upstream.requests[0][1])
        assert expected in upstream_headers
        assert b"Basic wrong" not in upstream_headers
    finally:
        await _stop_server(target_server)
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_http_connect_accepts_2xx_and_sends_host_header():
    target = TargetHttpServer()
    upstream = HttpProxyUpstream(connect_status=204)
    target_server, target_port = await _start_server(target.handler)
    upstream_server, upstream_port = await _start_server(upstream.handler)
    try:
        async with Socks5Proxy(f"http://127.0.0.1:{upstream_port}", connect_timeout=2.0) as proxy:
            response = await _socks5_request_through_local_proxy(proxy.get_local_url(), target_port)

        assert b"target-ok" in response
        connect_headers = b"".join(upstream.requests[0][1])
        assert f"Host: 127.0.0.1:{target_port}\r\n".encode("ascii") in connect_headers
    finally:
        await _stop_server(target_server)
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_socks5_upstream_encodes_idna_domain_bytes():
    upstream = CaptureSocks5Upstream()
    upstream_server, upstream_port = await _start_server(upstream.handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", upstream_port)
        try:
            await send_socks5_connect(reader, writer, "bücher.example", 443, timeout=2.0)
        finally:
            await _close_writer(writer)

        assert upstream.requests == [("xn--bcher-kva.example", 443)]
    finally:
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_local_socks5_rejects_unsupported_auth_method():
    async with Socks5Proxy("http://127.0.0.1:1", connect_timeout=2.0) as proxy:
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"\x05\xff"
        finally:
            await _close_writer(writer)


@pytest.mark.asyncio
async def test_local_socks5_reports_command_not_supported():
    async with Socks5Proxy("http://127.0.0.1:1", connect_timeout=2.0) as proxy:
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"\x05\x00"
            writer.write(b"\x05\x02\x00\x01" + socket.inet_aton("127.0.0.1") + (80).to_bytes(2, "big"))
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(10), timeout=2)
            assert reply[1] == 0x07
        finally:
            await _close_writer(writer)


@pytest.mark.asyncio
async def test_stop_closes_active_tunnel():
    async def hanging_target(reader, writer):
        try:
            await reader.read()
        finally:
            await _close_writer(writer)

    target_server, target_port = await _start_server(hanging_target)
    upstream = HttpProxyUpstream()
    upstream_server, upstream_port = await _start_server(upstream.handler)
    proxy = HttpProxy(f"http://127.0.0.1:{upstream_port}", connect_timeout=2.0)
    try:
        await proxy.start()
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            writer.write(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n\r\n".encode("ascii"))
            await writer.drain()
            response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
            assert b"200 Connection Established" in response

            await proxy.stop()
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        finally:
            await _close_writer(writer)
    finally:
        await proxy.stop()
        await _stop_server(target_server)
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_stop_closes_idle_accepted_client():
    proxy = HttpProxy("http://127.0.0.1:1", connect_timeout=2.0)
    try:
        await proxy.start()
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            await proxy.stop()
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        finally:
            await _close_writer(writer)
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_stop_closes_upstream_during_connect_handshake():
    upstream = HangingConnectUpstream()
    upstream_server, upstream_port = await _start_server(upstream.handler)
    proxy = HttpProxy(f"http://127.0.0.1:{upstream_port}", connect_timeout=10.0)
    try:
        await proxy.start()
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            writer.write(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(upstream.connected.wait(), timeout=2)

            await proxy.stop()
            await asyncio.wait_for(upstream.closed.wait(), timeout=2)
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        finally:
            await _close_writer(writer)
    finally:
        await proxy.stop()
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_stop_cancels_handler_during_pending_upstream_connect():
    proxy = HttpProxy("http://127.0.0.1:1", connect_timeout=10.0)
    connector = HangingConnector()
    proxy.upstream_connector = connector
    try:
        await proxy.start()
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            writer.write(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(connector.started.wait(), timeout=2)

            await proxy.stop()
            await asyncio.wait_for(connector.cancelled.wait(), timeout=2)
            assert await asyncio.wait_for(reader.read(), timeout=2) == b""
        finally:
            await _close_writer(writer)
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_local_http_rejects_too_many_headers():
    async with HttpProxy("http://127.0.0.1:1", connect_timeout=2.0) as proxy:
        parsed = urlparse(proxy.get_local_url())
        reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
        try:
            headers = "".join(f"X-Test-{index}: value\r\n" for index in range(101))
            writer.write(
                (
                    "GET http://127.0.0.1:1/ HTTP/1.1\r\n"
                    f"{headers}"
                    "\r\n"
                ).encode("ascii")
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=2)
            assert b"400 Bad Request" in response
        finally:
            await _close_writer(writer)


@pytest.mark.asyncio
async def test_proxy_binds_actual_ephemeral_port():
    async with HttpProxy("http://127.0.0.1:1", connect_timeout=0.1) as proxy:
        assert proxy.running is True
        assert proxy.local_port > 0
        assert proxy.get_local_url().startswith("http://127.0.0.1:")
    assert proxy.running is False


def test_https_upstream_opens_tls(monkeypatch):
    calls = {}

    async def fake_open_connection(host, port, **kwargs):
        calls["host"] = host
        calls["port"] = port
        calls["kwargs"] = kwargs
        return object(), object()

    async def fake_resolve(host, port):
        return host

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr("proxy_relay._transport.resolve_host", fake_resolve)
    monkeypatch.setattr("proxy_relay._transport.configure_socket", lambda writer: None)

    async def run():
        return await connect_upstream(
            "proxy.example",
            443,
            timeout=1.0,
            use_tls=True,
            server_hostname="proxy.example",
        )

    asyncio.run(run())

    assert calls["host"] == "proxy.example"
    assert calls["port"] == 443
    assert isinstance(calls["kwargs"]["ssl"], ssl.SSLContext)
    assert calls["kwargs"]["server_hostname"] == "proxy.example"


def test_parse_proxy_url_accepts_supported_schemes():
    cfg = parse_proxy_url("socks5://user:pass@127.0.0.1:1080")
    assert cfg["scheme"] == "socks5"
    assert cfg["host"] == "127.0.0.1"
    assert cfg["port"] == 1080
    assert cfg["username"] == "user"
    assert cfg["password"] == "pass"


def test_parse_proxy_url_rejects_unknown_scheme():
    with pytest.raises(ValueError, match="Unsupported proxy scheme"):
        parse_proxy_url("ftp://127.0.0.1:21")


def test_map_connect_error_uses_structured_socks5_rep():
    err = UpstreamConnectionError("SOCKS5 connect failed: 5", socks5_rep=5)
    assert map_connect_error_to_socks5_rep(err) == SOCKS5_CONNECTION_REFUSED


def test_map_connect_error_uses_os_errno():
    err = UpstreamConnectionError("boom", os_errno=getattr(__import__("errno"), "ECONNREFUSED"))
    assert map_connect_error_to_socks5_rep(err) == SOCKS5_CONNECTION_REFUSED


def test_map_connect_error_defaults_to_general_failure():
    assert map_connect_error_to_socks5_rep(RuntimeError("something else")) == SOCKS5_GENERAL_FAILURE


def test_map_connect_error_host_unreachable_message():
    err = UpstreamConnectionError("getaddrinfo failed")
    assert map_connect_error_to_socks5_rep(err) == SOCKS5_HOST_UNREACHABLE


@pytest.mark.asyncio
async def test_http_forwarding_injects_connection_close():
    target = TargetHttpServer()
    upstream = HttpProxyUpstream()
    target_server, target_port = await _start_server(target.handler)
    upstream_server, upstream_port = await _start_server(upstream.handler)
    try:
        async with HttpProxy(f"http://127.0.0.1:{upstream_port}", connect_timeout=2.0) as proxy:
            parsed = urlparse(proxy.get_local_url())
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
            try:
                writer.write(
                    f"GET http://127.0.0.1:{target_port}/probe HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{target_port}\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n"
                    .encode("ascii")
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), timeout=3)
            finally:
                await _close_writer(writer)

        assert b"target-ok" in response
        upstream_headers = b"".join(upstream.requests[0][1]).lower()
        assert b"connection: close" in upstream_headers
        assert b"connection: keep-alive" not in upstream_headers
    finally:
        await _stop_server(target_server)
        await _stop_server(upstream_server)


@pytest.mark.asyncio
async def test_half_close_forwards_fin_and_delivers_response():
    """Client shuts write side after request; reverse path must still deliver body."""

    async def echo_once(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.write(b"ECHO:" + data)
            await writer.drain()
            # Keep the write side open briefly so half-close path can drain.
            await asyncio.sleep(0.05)
        finally:
            await _close_writer(writer)

    target_server, target_port = await _start_server(echo_once)
    upstream = HttpProxyUpstream()
    upstream_server, upstream_port = await _start_server(upstream.handler)
    try:
        async with Socks5Proxy(
            f"http://127.0.0.1:{upstream_port}",
            connect_timeout=2.0,
            idle_timeout=5.0,
        ) as proxy:
            parsed = urlparse(proxy.get_local_url())
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
            try:
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(2), timeout=2) == b"\x05\x00"
                writer.write(
                    b"\x05\x01\x00\x01"
                    + socket.inet_aton("127.0.0.1")
                    + int(target_port).to_bytes(2, "big")
                )
                await writer.drain()
                reply = await asyncio.wait_for(reader.readexactly(10), timeout=2)
                assert reply[1] == 0x00

                payload = b"hello-half-close"
                writer.write(payload)
                await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()

                response = await asyncio.wait_for(reader.read(), timeout=3)
            finally:
                await _close_writer(writer)

        assert response == b"ECHO:" + payload
    finally:
        await _stop_server(target_server)
        await _stop_server(upstream_server)


def test_sync_create_proxy_and_stop_proxy():
    """Exercise the sync facade end-to-end against local fake upstreams."""
    import threading

    target = TargetHttpServer()
    upstream = HttpProxyUpstream()

    loop = asyncio.new_event_loop()
    servers = {}
    ready = threading.Event()

    def run_servers():
        asyncio.set_event_loop(loop)

        async def setup():
            target_server, target_port = await _start_server(target.handler)
            upstream_server, upstream_port = await _start_server(upstream.handler)
            servers["target"] = target_server
            servers["upstream"] = upstream_server
            servers["target_port"] = target_port
            servers["upstream_port"] = upstream_port
            ready.set()

        loop.run_until_complete(setup())
        loop.run_forever()

    thread = threading.Thread(target=run_servers, daemon=True)
    thread.start()
    assert ready.wait(timeout=5)

    local_url = None
    try:
        local_url = proxy_relay.create_proxy(
            f"http://127.0.0.1:{servers['upstream_port']}",
            local_type="http",
            connect_timeout=2.0,
            idle_timeout=5.0,
            timeout=5.0,
        )
        assert local_url.startswith("http://127.0.0.1:")

        async def probe():
            return await _http_request_through_local_proxy(local_url, servers["target_port"])

        response = asyncio.run(probe())
        assert b"target-ok" in response
        assert b"200 OK" in response
    finally:
        if local_url is not None:
            stop_proxy(local_url)

        async def teardown():
            for key in ("target", "upstream"):
                server = servers.get(key)
                if server is not None:
                    server.close()
                    await server.wait_closed()
            loop.stop()

        future = asyncio.run_coroutine_threadsafe(teardown(), loop)
        try:
            future.result(timeout=5)
        except Exception:
            loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)


def test_background_loop_manager_starts_once():
    from proxy_relay._sync import BackgroundLoopManager

    manager = BackgroundLoopManager()
    try:
        loop1 = manager.loop
        loop2 = manager.loop
        assert loop1 is loop2
        assert loop1.is_running()
        result = manager.run(asyncio.sleep(0, result=42), timeout=2)
        assert result == 42
    finally:
        manager.shutdown()


def test_stop_proxy_unknown_url_is_noop():
    stop_proxy("http://127.0.0.1:1")  # must not raise


def test_upstream_connection_error_carries_fields():
    err = UpstreamConnectionError("x", socks5_rep=4, os_errno=101)
    assert err.socks5_rep == 4
    assert err.os_errno == 101
    assert isinstance(err, ProxyError)

