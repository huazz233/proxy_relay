"""HTTP and SOCKS5 protocol codec helpers."""

import asyncio
import base64
import errno
import socket
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ._errors import ClientConnectionError, ProxyError, UpstreamConnectionError
from ._transport import RELAY_CHUNK_SIZE, STREAM_LIMIT  # noqa: F401  re-exported for callers

MAX_LINE_SIZE = 8192
MAX_DOMAIN_LEN = 255
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 100

SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_USERPASS = 0x02
SOCKS5_NO_ACCEPTABLE_METHODS = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

SOCKS5_SUCCESS = 0x00
SOCKS5_GENERAL_FAILURE = 0x01
SOCKS5_NETWORK_UNREACHABLE = 0x03
SOCKS5_HOST_UNREACHABLE = 0x04
SOCKS5_CONNECTION_REFUSED = 0x05
SOCKS5_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    """Extract SNI hostname from a TLS ClientHello record, if present.

    Public utility retained for external callers. Returns None on any
    malformed or non-ClientHello input.
    """
    data_len = len(data)
    # TLS record header (5) + handshake header (4) + client_version (2)
    # + random (32) = 43 minimum before session_id length byte.
    if data_len < 43 or data[0] != 0x16 or data[5] != 0x01:
        return None

    pos = 43
    if pos >= data_len:
        return None
    pos += 1 + data[pos]  # session_id

    if pos + 2 > data_len:
        return None
    pos += 2 + int.from_bytes(data[pos:pos + 2], 'big')  # cipher_suites

    if pos >= data_len:
        return None
    pos += 1 + data[pos]  # compression_methods

    if pos + 2 > data_len:
        return None
    extensions_end = pos + 2 + int.from_bytes(data[pos:pos + 2], 'big')
    pos += 2

    while pos + 4 <= data_len and pos < extensions_end:
        ext_type = int.from_bytes(data[pos:pos + 2], 'big')
        ext_len = int.from_bytes(data[pos + 2:pos + 4], 'big')
        pos += 4

        if ext_type == 0 and pos + ext_len <= data_len:
            # server_name extension: list_len(2) + name_type(1) + name_len(2) + name
            if pos + 5 <= data_len and data[pos + 2] == 0:
                name_len = int.from_bytes(data[pos + 3:pos + 5], 'big')
                if pos + 5 + name_len <= data_len:
                    try:
                        return data[pos + 5:pos + 5 + name_len].decode('ascii')
                    except UnicodeDecodeError:
                        return None
            return None

        pos += ext_len

    return None


@dataclass
class HttpRequest:
    raw_line: bytes
    method: str
    target: str
    version: str
    headers: List[bytes]

    @property
    def is_connect(self) -> bool:
        return self.method.upper() == 'CONNECT'


def parse_proxy_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ['http', 'https', 'socks5', 'socks5h']:
        raise ValueError(f"Unsupported proxy scheme: {scheme}")

    if not parsed.hostname or not parsed.port:
        raise ValueError(f"Invalid proxy URL: {url}")

    if not (1 <= parsed.port <= 65535):
        raise ValueError(f"Invalid port: {parsed.port}")

    return {
        'scheme': scheme,
        'host': parsed.hostname,
        'port': parsed.port,
        'username': parsed.username,
        'password': parsed.password,
    }


def is_socks_scheme(scheme: str) -> bool:
    return scheme in ['socks5', 'socks5h']


def parse_host_port(target: str) -> Tuple[str, int]:
    try:
        if target.startswith('['):
            bracket_end = target.find(']')
            if bracket_end == -1:
                raise ValueError(f"Invalid IPv6 address format: {target}")
            host = target[1:bracket_end]
            rest = target[bracket_end + 1:]
            if not rest.startswith(':'):
                raise ValueError(f"Missing port in target: {target}")
            port = int(rest[1:])
        else:
            host, port_text = target.rsplit(':', 1)
            port = int(port_text)
    except ValueError as exc:
        raise ClientConnectionError(f"Invalid target authority: {target}") from exc

    if not host:
        raise ClientConnectionError(f"Invalid target host: {target}")
    if not (1 <= port <= 65535):
        raise ClientConnectionError(f"Invalid target port: {port}")
    return host, port


def format_host_port(host: str, port: int) -> str:
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return f"[{host}]:{port}"
    except (OSError, ValueError):
        pass

    if ':' in host and not host.startswith('['):
        return f"[{host}]:{port}"

    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ProxyError(f"Invalid target host: {host}") from exc
    return f"{host}:{port}"


def encode_domain_name(host: str, label: str = "domain") -> bytes:
    try:
        encoded = host.encode('idna')
    except UnicodeError as exc:
        raise ProxyError(f"Invalid {label}: {host}") from exc
    if not (1 <= len(encoded) <= MAX_DOMAIN_LEN):
        raise ProxyError(f"{label} length out of range: {len(encoded)} bytes")
    return encoded


def has_auth(auth_config: Optional[dict]) -> bool:
    return bool(auth_config and auth_config.get('username') and auth_config.get('password'))


async def read_exact(reader: asyncio.StreamReader, n: int, timeout: Optional[float] = None, *,
                     error_cls=ClientConnectionError) -> bytes:
    try:
        if timeout is not None:
            return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
        return await reader.readexactly(n)
    except asyncio.TimeoutError:
        raise error_cls(f"Read timeout for {n} bytes")
    except asyncio.IncompleteReadError:
        raise error_cls(f"Connection closed unexpectedly, expected {n} bytes")


async def read_line(reader: asyncio.StreamReader, timeout: Optional[float] = None, *,
                    error_cls=ClientConnectionError, label: str = "line") -> bytes:
    try:
        if timeout is not None:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        else:
            line = await reader.readline()
    except asyncio.TimeoutError:
        raise error_cls(f"Read {label} timeout")
    except ValueError as exc:
        raise error_cls(f"{label} too long: {exc}")

    if len(line) > MAX_LINE_SIZE:
        raise error_cls(f"{label} too long: {len(line)} > {MAX_LINE_SIZE}")
    return line


async def read_http_headers(reader: asyncio.StreamReader, timeout: Optional[float],
                            label: str = "HTTP request header",
                            error_cls=ClientConnectionError) -> List[bytes]:
    headers = []
    total_size = 0
    while True:
        line = await read_line(reader, timeout, error_cls=error_cls, label=label)
        if not line or line == b'\r\n':
            return headers
        total_size += len(line)
        if len(headers) >= MAX_HEADER_COUNT:
            raise error_cls(f"{label} count too large: {len(headers) + 1} > {MAX_HEADER_COUNT}")
        if total_size > MAX_HEADER_BYTES:
            raise error_cls(f"{label} block too large: {total_size} > {MAX_HEADER_BYTES}")
        headers.append(line)


async def read_http_request(reader: asyncio.StreamReader,
                            timeout: Optional[float],
                            initial_data: bytes = b'') -> Optional[HttpRequest]:
    # Overall deadline so a slowloris client cannot stretch one handshake
    # across MAX_HEADER_COUNT * per-line timeouts.
    deadline = None
    if timeout is not None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

    def remaining() -> Optional[float]:
        if deadline is None:
            return timeout
        left = deadline - asyncio.get_running_loop().time()
        if left <= 0:
            raise ClientConnectionError("HTTP request parse deadline exceeded")
        return left

    if initial_data:
        request_line = initial_data + await read_line(reader, remaining(), label="HTTP request line")
        if len(request_line) > MAX_LINE_SIZE:
            raise ClientConnectionError(
                f"HTTP request line too long: {len(request_line)} > {MAX_LINE_SIZE}"
            )
    else:
        request_line = await read_line(reader, remaining(), label="HTTP request line")

    if not request_line:
        return None

    try:
        request_text = request_line.decode('utf-8').strip()
    except UnicodeDecodeError as exc:
        raise ClientConnectionError(f"Invalid HTTP request line encoding: {exc}") from exc
    if not request_text:
        return None

    parts = request_text.split()
    if len(parts) < 3:
        raise ClientConnectionError(f"Invalid HTTP request line: {request_text}")

    headers = await read_http_headers(reader, remaining(), label="HTTP request header")
    return HttpRequest(
        raw_line=request_line,
        method=parts[0],
        target=parts[1],
        version=parts[2],
        headers=headers,
    )


def build_basic_proxy_auth(auth_config: dict) -> bytes:
    auth_str = f"{auth_config['username']}:{auth_config['password']}"
    auth_header = base64.b64encode(auth_str.encode()).decode()
    return f"Proxy-Authorization: Basic {auth_header}\r\n".encode()


def build_http_connect_request(target_host: str, target_port: int,
                               auth_config: Optional[dict] = None) -> bytes:
    authority = format_host_port(target_host, target_port)
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode()
    if has_auth(auth_config):
        request += build_basic_proxy_auth(auth_config)
    return request + b"\r\n"


async def send_http_connect(upstream_reader: asyncio.StreamReader,
                            upstream_writer: asyncio.StreamWriter,
                            target_host: str,
                            target_port: int,
                            auth_config: Optional[dict] = None,
                            timeout: float = 10.0) -> None:
    upstream_writer.write(build_http_connect_request(target_host, target_port, auth_config))
    await upstream_writer.drain()

    async def read_response() -> None:
        response_line = await read_line(
            upstream_reader,
            timeout,
            error_cls=UpstreamConnectionError,
            label="HTTP response line",
        )
        if not response_line:
            raise UpstreamConnectionError("No response from upstream")

        response = response_line.decode('utf-8', errors='replace').strip()
        await read_http_headers(
            upstream_reader,
            timeout,
            label="HTTP response header",
            error_cls=UpstreamConnectionError,
        )

        parts = response.split(None, 2)
        try:
            status_code = int(parts[1])
        except (IndexError, ValueError):
            raise UpstreamConnectionError(f"Invalid CONNECT response: {response}")
        if not (200 <= status_code <= 299):
            raise UpstreamConnectionError(f"CONNECT failed: {response}")

    try:
        await asyncio.wait_for(read_response(), timeout=timeout)
    except asyncio.TimeoutError:
        raise UpstreamConnectionError(f"HTTP CONNECT timeout ({timeout}s)")


def socks5_reply(rep: int) -> bytes:
    return b'\x05' + bytes([rep]) + b'\x00\x01\x00\x00\x00\x00\x00\x00'


async def send_socks5_reply(writer: asyncio.StreamWriter, rep: int,
                            timeout: Optional[float] = None) -> None:
    writer.write(socks5_reply(rep))
    if timeout is not None:
        await asyncio.wait_for(writer.drain(), timeout=timeout)
    else:
        await writer.drain()


def map_connect_error_to_socks5_rep(error: Exception) -> int:
    if isinstance(error, UpstreamConnectionError) and error.socks5_rep is not None:
        return error.socks5_rep

    os_errno = None
    if isinstance(error, UpstreamConnectionError):
        os_errno = error.os_errno
    if os_errno is None:
        cause = error.__cause__
        if isinstance(cause, OSError):
            os_errno = cause.errno
        elif isinstance(error, OSError):
            os_errno = error.errno

    if os_errno is not None:
        refused = (errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED))
        net_unreach = (errno.ENETUNREACH, getattr(errno, "WSAENETUNREACH", errno.ENETUNREACH))
        host_unreach = (errno.EHOSTUNREACH, getattr(errno, "WSAEHOSTUNREACH", errno.EHOSTUNREACH))
        if os_errno in refused:
            return SOCKS5_CONNECTION_REFUSED
        if os_errno in net_unreach:
            return SOCKS5_NETWORK_UNREACHABLE
        if os_errno in host_unreach:
            return SOCKS5_HOST_UNREACHABLE

    text = str(error).lower()
    if "name or service not known" in text or "getaddrinfo failed" in text:
        return SOCKS5_HOST_UNREACHABLE
    if "connection refused" in text:
        return SOCKS5_CONNECTION_REFUSED
    if "network is unreachable" in text or "host is unreachable" in text:
        return SOCKS5_HOST_UNREACHABLE
    return SOCKS5_GENERAL_FAILURE


def build_socks5_connect_request(target_host: str, target_port: int) -> bytes:
    if not (1 <= target_port <= 65535):
        raise ProxyError(f"Invalid target port: {target_port}")

    request = bytearray(b'\x05\x01\x00')
    try:
        request.append(SOCKS5_ATYP_IPV4)
        request.extend(socket.inet_pton(socket.AF_INET, target_host))
    except (OSError, ValueError):
        try:
            request[-1] = SOCKS5_ATYP_IPV6
            request.extend(socket.inet_pton(socket.AF_INET6, target_host))
        except (OSError, ValueError):
            request[-1] = SOCKS5_ATYP_DOMAIN
            domain = encode_domain_name(target_host, "target domain")
            request.append(len(domain))
            request.extend(domain)

    request.extend(target_port.to_bytes(2, 'big'))
    return bytes(request)


async def send_socks5_connect(upstream_reader: asyncio.StreamReader,
                              upstream_writer: asyncio.StreamWriter,
                              target_host: str,
                              target_port: int,
                              auth_config: Optional[dict] = None,
                              timeout: float = 10.0) -> None:
    """Perform SOCKS5 handshake + CONNECT on an established TCP connection."""
    if auth_config and (
        auth_config.get('username') is not None or auth_config.get('password') is not None
    ) and not has_auth(auth_config):
        raise ProxyError("SOCKS5 credentials require non-empty username and password")

    auth_methods = [SOCKS5_NO_AUTH]
    if has_auth(auth_config):
        auth_methods.append(SOCKS5_USERPASS)

    upstream_writer.write(b'\x05' + bytes([len(auth_methods)]) + bytes(auth_methods))
    await upstream_writer.drain()

    ver, chosen_method = await read_exact(
        upstream_reader,
        2,
        timeout,
        error_cls=UpstreamConnectionError,
    )
    if ver != SOCKS5_VERSION or chosen_method == SOCKS5_NO_ACCEPTABLE_METHODS:
        raise UpstreamConnectionError("SOCKS5 handshake failed")

    if chosen_method == SOCKS5_USERPASS:
        if not auth_config or not auth_config.get('username') or not auth_config.get('password'):
            raise UpstreamConnectionError("SOCKS5 server requires auth but no credentials provided")
        username = auth_config['username'].encode('utf-8')
        password = auth_config['password'].encode('utf-8')
        if not (1 <= len(username) <= MAX_DOMAIN_LEN):
            raise ProxyError(f"Username length out of range: {len(username)} bytes")
        if not (1 <= len(password) <= MAX_DOMAIN_LEN):
            raise ProxyError(f"Password length out of range: {len(password)} bytes")
        upstream_writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await upstream_writer.drain()
        ver, status = await read_exact(upstream_reader, 2, timeout, error_cls=UpstreamConnectionError)
        if ver != 0x01 or status != 0x00:
            raise UpstreamConnectionError("SOCKS5 authentication failed")
    elif chosen_method != SOCKS5_NO_AUTH:
        raise UpstreamConnectionError(f"SOCKS5 unsupported auth method: {chosen_method}")

    upstream_writer.write(build_socks5_connect_request(target_host, target_port))
    await upstream_writer.drain()

    header = await read_exact(upstream_reader, 4, timeout, error_cls=UpstreamConnectionError)
    if header[0] != SOCKS5_VERSION:
        raise UpstreamConnectionError("SOCKS5 invalid response version")
    if header[1] != SOCKS5_SUCCESS:
        raise UpstreamConnectionError(
            f"SOCKS5 connect failed: {header[1]}",
            socks5_rep=header[1],
        )

    atyp = header[3]
    if atyp == SOCKS5_ATYP_IPV4:
        await read_exact(upstream_reader, 4 + 2, timeout, error_cls=UpstreamConnectionError)
    elif atyp == SOCKS5_ATYP_IPV6:
        await read_exact(upstream_reader, 16 + 2, timeout, error_cls=UpstreamConnectionError)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        domain_len = (await read_exact(upstream_reader, 1, timeout, error_cls=UpstreamConnectionError))[0]
        await read_exact(upstream_reader, domain_len + 2, timeout, error_cls=UpstreamConnectionError)
    else:
        raise UpstreamConnectionError(f"SOCKS5 unknown address type: {atyp}")


async def read_socks5_address(reader: asyncio.StreamReader,
                              atyp: int,
                              timeout: Optional[float]) -> Tuple[str, int, int]:
    if atyp == SOCKS5_ATYP_IPV4:
        addr_bytes = await read_exact(reader, 4, timeout)
        target_host = socket.inet_ntoa(addr_bytes)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        addr_len = (await read_exact(reader, 1, timeout))[0]
        if addr_len > MAX_DOMAIN_LEN:
            raise ClientConnectionError(f"Domain length out of range: {addr_len} > {MAX_DOMAIN_LEN}")
        try:
            target_host = (await read_exact(reader, addr_len, timeout)).decode('ascii')
        except UnicodeDecodeError as exc:
            raise ClientConnectionError(f"Invalid SOCKS5 domain encoding: {exc}") from exc
    elif atyp == SOCKS5_ATYP_IPV6:
        addr_bytes = await read_exact(reader, 16, timeout)
        target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise ClientConnectionError(f"Unsupported SOCKS5 address type: {atyp}")

    target_port = struct.unpack('>H', await read_exact(reader, 2, timeout))[0]
    return target_host, target_port, atyp
