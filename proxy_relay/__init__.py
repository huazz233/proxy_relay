#!/usr/bin/env python3
"""多协议代理中转器 - 支持HTTP/HTTPS/SOCKS5/SOCKS5H协议互转，本地代理无需账密认证"""

import asyncio
import atexit
import base64
import socket
import struct
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

__version__ = "1.0.0"
__author__ = "huazz233"

# 协议限制常量
MAX_LINE_SIZE = 8192  # HTTP请求行最大长度
MAX_DOMAIN_LEN = 255  # 域名最大长度(RFC1928)


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    try:
        data_len = len(data)
        if data_len < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None

        pos = 43
        if pos >= data_len:
            return None
        pos += 1 + data[pos]

        if pos + 2 > data_len:
            return None
        pos += 2 + int.from_bytes(data[pos:pos + 2], 'big')

        if pos >= data_len:
            return None
        pos += 1 + data[pos]

        if pos + 2 > data_len:
            return None
        extensions_end = pos + 2 + int.from_bytes(data[pos:pos + 2], 'big')
        pos += 2

        while pos + 4 <= data_len and pos < extensions_end:
            ext_type = int.from_bytes(data[pos:pos + 2], 'big')
            ext_len = int.from_bytes(data[pos + 2:pos + 4], 'big')
            pos += 4

            if ext_type == 0 and pos + ext_len <= data_len:
                if pos + 5 <= data_len and data[pos + 2] == 0:
                    name_len = int.from_bytes(data[pos + 3:pos + 5], 'big')
                    if pos + 5 + name_len <= data_len:
                        return data[pos + 5:pos + 5 + name_len].decode('ascii', errors='ignore')
                return None

            pos += ext_len

        return None
    except Exception:
        return None


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        return s.getsockname()[1]


def parse_proxy_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ['http', 'https', 'socks5', 'socks5h']:
        raise ValueError(f"不支持的协议: {scheme}")

    if not parsed.hostname or not parsed.port:
        raise ValueError(f"无效的代理URL: {url}")

    if not (1 <= parsed.port <= 65535):
        raise ValueError(f"无效的端口: {parsed.port}")

    return {
        'scheme': scheme,
        'host': parsed.hostname,
        'port': parsed.port,
        'username': parsed.username,
        'password': parsed.password
    }


def is_socks_scheme(scheme: str) -> bool:
    return scheme in ['socks5', 'socks5h']


class ProxyError(Exception):
    pass


class UpstreamConnectionError(ProxyError):
    pass


class ClientConnectionError(ProxyError):
    pass


async def _read_exact(reader: asyncio.StreamReader, n: int, timeout: Optional[float] = None):
    try:
        if timeout:
            return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
        return await reader.readexactly(n)
    except asyncio.TimeoutError:
        raise ClientConnectionError(f"读取{n}字节超时")
    except asyncio.IncompleteReadError:
        raise ClientConnectionError(f"连接意外关闭,期望{n}字节")


async def connect_upstream(host: str, port: int, timeout: Optional[float] = None):
    try:
        if timeout:
            return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return await asyncio.open_connection(host, port)
    except asyncio.TimeoutError:
        raise UpstreamConnectionError(f"连接超时 {host}:{port}")
    except Exception as e:
        raise UpstreamConnectionError(f"连接失败 {host}:{port} - {e}")


async def send_http_connect(upstream_reader, upstream_writer, target_host: str, target_port: int,
                            auth_config: dict = None, timeout: float = 10.0) -> bool:
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"

    if auth_config and auth_config.get('username') and auth_config.get('password'):
        auth_str = f"{auth_config['username']}:{auth_config['password']}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        request += f"Proxy-Authorization: Basic {auth_header}\r\n"

    request += "\r\n"
    upstream_writer.write(request.encode())
    await upstream_writer.drain()

    async def read_response():
        response_line = await upstream_reader.readline()
        if not response_line:
            raise UpstreamConnectionError("上游无响应")
        if len(response_line) > MAX_LINE_SIZE:
            raise UpstreamConnectionError(f"HTTP响应行过长: {len(response_line)} > {MAX_LINE_SIZE}")

        response = response_line.decode('utf-8', errors='ignore').strip()

        while True:
            line = await upstream_reader.readline()
            if len(line) > MAX_LINE_SIZE:
                raise UpstreamConnectionError(f"HTTP响应行过长: {len(line)} > {MAX_LINE_SIZE}")
            if not line or line == b'\r\n':
                break

        if "200" not in response:
            raise UpstreamConnectionError(f"CONNECT失败: {response}")

        return True

    try:
        return await asyncio.wait_for(read_response(), timeout=timeout)
    except asyncio.TimeoutError:
        raise UpstreamConnectionError(f"HTTP CONNECT超时({timeout}s)")


class BaseProxy(ABC):

    def __init__(self, upstream_url: str, connect_timeout: Optional[float] = 30.0,
                 idle_timeout: Optional[float] = 300.0):
        self.upstream_config = parse_proxy_url(upstream_url)
        self.local_port = find_free_port()
        self.local_host = '127.0.0.1'
        self.running = False
        self._server = None
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout

    async def start(self) -> str:
        if self.running:
            return self.get_local_url()

        self.running = True
        self._server = await asyncio.start_server(
            self._handle_client,
            self.local_host,
            self.local_port
        )
        return self.get_local_url()

    async def stop(self):
        if not self.running:
            return

        self.running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @abstractmethod
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        pass

    @abstractmethod
    def get_local_url(self) -> str:
        pass

    async def _relay_data(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                          upstream_reader: asyncio.StreamReader, upstream_writer: asyncio.StreamWriter):
        async def copy_data(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while True:
                    if self.idle_timeout is not None:
                        try:
                            data = await asyncio.wait_for(src.read(8192), timeout=self.idle_timeout)
                        except asyncio.TimeoutError:
                            break
                    else:
                        data = await src.read(8192)

                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    if not dst.is_closing():
                        dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            copy_data(client_reader, upstream_writer),
            copy_data(upstream_reader, client_writer),
            return_exceptions=True
        )

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


def _create_proxy_instance(upstream_url: str, local_type: str, connect_timeout: float, idle_timeout: float):
    if not upstream_url:
        raise ValueError("上游代理URL不能为空")

    if local_type not in ['http', 'socks5']:
        raise ValueError(f"不支持的本地代理类型: {local_type}")

    if local_type == 'http':
        return HttpProxy(upstream_url, connect_timeout=connect_timeout, idle_timeout=idle_timeout)
    else:
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
        for proxy in self._proxies.values():
            await proxy.stop()
        self._proxies.clear()

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        await self.stop_all()
        return False

    def __repr__(self):
        return f"ProxyManager(active_proxies={len(self._proxies)})"


class HttpProxy(BaseProxy):

    def get_local_url(self) -> str:
        return f"http://{self.local_host}:{self.local_port}"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readline()
            if not request_line:
                return

            request = request_line.decode('utf-8', errors='ignore').strip()
            if not request:
                return

            parts = request.split()
            if len(parts) < 3:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            if parts[0].upper() == 'CONNECT':
                await self._handle_connect(reader, writer, request)
            else:
                await self._handle_http_request(reader, writer, request_line)

        except Exception:
            try:
                writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, request: str):
        try:
            target = request.split()[1]
            target_host, target_port_str = target.split(':', 1)
            target_port = int(target_port_str)

            upstream_reader, upstream_writer = await connect_upstream(
                self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
            )

            await send_http_connect(
                upstream_reader, upstream_writer, target_host, target_port,
                self.upstream_config, self.connect_timeout
            )

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def skip_headers():
                while True:
                    line = await reader.readline()
                    if len(line) > MAX_LINE_SIZE:
                        raise ClientConnectionError(f"HTTP请求行过长: {len(line)} > {MAX_LINE_SIZE}")
                    if not line or line == b'\r\n':
                        break

            try:
                await asyncio.wait_for(skip_headers(), timeout=self.connect_timeout)
            except asyncio.TimeoutError:
                raise ClientConnectionError("读取客户端请求头超时")

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    async def _handle_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                   request_line: bytes):
        try:
            upstream_reader, upstream_writer = await connect_upstream(
                self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
            )

            upstream_writer.write(request_line)

            async def forward_headers():
                auth_added = False
                while True:
                    line = await reader.readline()
                    if len(line) > MAX_LINE_SIZE:
                        raise ClientConnectionError(f"HTTP请求行过长: {len(line)} > {MAX_LINE_SIZE}")

                    if line == b'\r\n':
                        if not auth_added and self.upstream_config.get('username') and self.upstream_config.get(
                                'password'):
                            auth_str = f"{self.upstream_config['username']}:{self.upstream_config['password']}"
                            auth_header = base64.b64encode(auth_str.encode()).decode()
                            upstream_writer.write(f"Proxy-Authorization: Basic {auth_header}\r\n".encode())
                        upstream_writer.write(line)
                        break

                    if line.lower().startswith(b'proxy-authorization:'):
                        auth_added = True

                    upstream_writer.write(line)

            try:
                await asyncio.wait_for(forward_headers(), timeout=self.connect_timeout)
            except asyncio.TimeoutError:
                raise ClientConnectionError("读取客户端请求头超时")

            await upstream_writer.drain()
            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass


class Socks5Proxy(BaseProxy):
    """SOCKS5代理,支持双协议"""

    def get_local_url(self) -> str:
        return f"socks5://{self.local_host}:{self.local_port}"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            initial_data = await _read_exact(reader, 1, self.connect_timeout)

            if initial_data and initial_data[0] == 0x05:
                await self._handle_socks5(reader, writer, initial_data)
            else:
                await self._handle_http(reader, writer, initial_data)

        except Exception:
            pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    async def _handle_socks5(self, reader, writer, initial_data):
        try:
            if initial_data[0] != 0x05:
                return

            nmethods = (await _read_exact(reader, 1, self.connect_timeout))[0]
            await _read_exact(reader, nmethods, self.connect_timeout)

            writer.write(b'\x05\x00')
            await writer.drain()

            ver, cmd, _, atyp = await _read_exact(reader, 4, self.connect_timeout)

            if ver != 0x05 or cmd != 0x01:
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            target_host, target_port, addr_type = await self._parse_address(reader, atyp)
            if not target_host:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            first_packet = None
            if addr_type in (0x01, 0x04):
                writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()

                try:
                    first_packet = await asyncio.wait_for(reader.read(8192), timeout=self.connect_timeout)
                    if first_packet:
                        sni_domain = extract_sni_from_client_hello(first_packet)
                        if sni_domain:
                            target_host = sni_domain
                except Exception:
                    pass

            try:
                upstream_reader, upstream_writer = await self._connect_upstream(target_host, target_port)
            except Exception:
                if not first_packet:
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                return

            if not first_packet:
                writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
            else:
                try:
                    upstream_writer.write(first_packet)
                    await upstream_writer.drain()
                except Exception:
                    return

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception:
            try:
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
            except Exception:
                pass

    async def _handle_http(self, reader, writer, initial_data):
        try:
            request_line_bytes = initial_data + await reader.readline()
            if len(request_line_bytes) > MAX_LINE_SIZE:
                raise ClientConnectionError(f"HTTP请求行过长: {len(request_line_bytes)} > {MAX_LINE_SIZE}")

            request_line = request_line_bytes.decode('utf-8', errors='ignore').strip()
            parts = request_line.split()

            if len(parts) < 3 or parts[0].upper() != 'CONNECT':
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            target_host, target_port_str = parts[1].split(':', 1)
            target_port = int(target_port_str)

            async def skip_request_headers():
                while True:
                    line = await reader.readline()
                    if len(line) > MAX_LINE_SIZE:
                        raise ClientConnectionError(f"HTTP请求行过长: {len(line)} > {MAX_LINE_SIZE}")
                    if not line or line == b'\r\n':
                        break

            try:
                await asyncio.wait_for(skip_request_headers(), timeout=self.connect_timeout)
            except asyncio.TimeoutError:
                raise ClientConnectionError("读取客户端请求头超时")

            upstream_reader, upstream_writer = await self._connect_upstream(target_host, target_port)

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    async def _parse_address(self, reader, atyp: int) -> Tuple[str, int]:
        try:
            if atyp == 0x01:  # IPv4
                addr_bytes = await _read_exact(reader, 4, self.connect_timeout)
                target_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # 域名
                addr_len = (await _read_exact(reader, 1, self.connect_timeout))[0]
                if addr_len > MAX_DOMAIN_LEN:
                    raise ProxyError(f"域名长度超限: {addr_len} > {MAX_DOMAIN_LEN}")
                target_host = (await _read_exact(reader, addr_len, self.connect_timeout)).decode('ascii')
            elif atyp == 0x04:  # IPv6
                addr_bytes = await _read_exact(reader, 16, self.connect_timeout)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                return None, None

            target_port = struct.unpack('>H', await _read_exact(reader, 2, self.connect_timeout))[0]
            return target_host, target_port, atyp
        except Exception:
            return None, None, None

    async def _connect_upstream(self, target_host: str, target_port: int):
        if is_socks_scheme(self.upstream_config['scheme']):
            try:
                return await self._connect_socks5(target_host, target_port)
            except Exception:
                return await self._connect_http(target_host, target_port)
        return await self._connect_http(target_host, target_port)

    async def _connect_http(self, target_host: str, target_port: int):
        upstream_reader, upstream_writer = await connect_upstream(
            self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
        )
        await send_http_connect(upstream_reader, upstream_writer, target_host, target_port, self.upstream_config,
                                self.connect_timeout)
        return upstream_reader, upstream_writer

    async def _connect_socks5(self, target_host: str, target_port: int):
        upstream_reader, upstream_writer = await connect_upstream(
            self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
        )

        auth_methods = [0x00]
        if self.upstream_config.get('username') and self.upstream_config.get('password'):
            auth_methods.append(0x02)

        upstream_writer.write(b'\x05' + bytes([len(auth_methods)]) + bytes(auth_methods))
        await upstream_writer.drain()

        ver, chosen_method = await _read_exact(upstream_reader, 2, self.connect_timeout)
        if ver != 0x05 or chosen_method == 0xFF:
            raise UpstreamConnectionError("SOCKS5握手失败")

        if chosen_method == 0x02:
            username = self.upstream_config['username'].encode('utf-8')
            password = self.upstream_config['password'].encode('utf-8')

            if len(username) > MAX_DOMAIN_LEN:
                raise ProxyError(f"用户名长度超限: {len(username)} > {MAX_DOMAIN_LEN}")
            if len(password) > MAX_DOMAIN_LEN:
                raise ProxyError(f"密码长度超限: {len(password)} > {MAX_DOMAIN_LEN}")

            upstream_writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
            await upstream_writer.drain()

            ver, status = await _read_exact(upstream_reader, 2, self.connect_timeout)
            if ver != 0x01 or status != 0x00:
                raise UpstreamConnectionError("SOCKS5认证失败")

        req = bytearray(b'\x05\x01\x00')

        is_ipv4 = False
        is_ipv6 = False
        try:
            socket.inet_pton(socket.AF_INET, target_host)
            is_ipv4 = True
        except (socket.error, OSError, AttributeError):
            try:
                socket.inet_pton(socket.AF_INET6, target_host)
                is_ipv6 = True
            except (socket.error, OSError, AttributeError):
                pass

        if is_ipv4:
            req.append(0x01)
            req.extend(socket.inet_pton(socket.AF_INET, target_host))
        elif is_ipv6:
            req.append(0x04)
            req.extend(socket.inet_pton(socket.AF_INET6, target_host))
        else:
            if len(target_host) > MAX_DOMAIN_LEN:
                raise ProxyError(f"目标域名长度超限: {len(target_host)} > {MAX_DOMAIN_LEN}")
            req.append(0x03)
            req.append(len(target_host))
            req.extend(target_host.encode('ascii'))

        req.extend(target_port.to_bytes(2, 'big'))
        upstream_writer.write(req)
        await upstream_writer.drain()

        response = await _read_exact(upstream_reader, 10, self.connect_timeout)
        if response[1] != 0x00:
            raise UpstreamConnectionError(f"SOCKS5连接失败: {response[1]}")

        return upstream_reader, upstream_writer


_background_loop = None
_background_thread = None
_loop_lock = threading.Lock()
_proxy_registry = {}
_registry_lock = threading.Lock()


def _get_background_loop():
    global _background_loop, _background_thread

    with _loop_lock:
        if _background_loop is None or not _background_loop.is_running():
            _background_loop = asyncio.new_event_loop()

            def run_loop():
                asyncio.set_event_loop(_background_loop)
                _background_loop.run_forever()

            _background_thread = threading.Thread(target=run_loop, daemon=True)
            _background_thread.start()

        return _background_loop


def _run_async(coro, timeout=None):
    loop = _get_background_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        future.cancel()
        raise ProxyError(f"操作超时({timeout}s)")


async def create_proxy_async(upstream_url: str, local_type: str = 'http', connect_timeout: float = 30.0,
                             idle_timeout: float = 300.0) -> str:
    proxy = _create_proxy_instance(upstream_url, local_type, connect_timeout, idle_timeout)
    local_url = await proxy.start()

    with _registry_lock:
        _proxy_registry[local_url] = proxy

    return local_url


async def create_http_proxy_async(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0) -> str:
    return await create_proxy_async(upstream_url, 'http', connect_timeout=connect_timeout, idle_timeout=idle_timeout)


async def create_socks5_proxy_async(upstream_url: str, connect_timeout: float = 30.0,
                                    idle_timeout: float = 300.0) -> str:
    return await create_proxy_async(upstream_url, 'socks5', connect_timeout=connect_timeout, idle_timeout=idle_timeout)


def create_proxy(upstream_url: str, local_type: str = 'http', connect_timeout: float = 30.0,
                 idle_timeout: float = 300.0, timeout: float = 30.0) -> str:
    return _run_async(create_proxy_async(upstream_url, local_type, connect_timeout, idle_timeout), timeout=timeout)


def create_http_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0,
                      timeout: float = 30.0) -> str:
    return create_proxy(upstream_url, 'http', connect_timeout=connect_timeout, idle_timeout=idle_timeout,
                        timeout=timeout)


def create_socks5_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0,
                        timeout: float = 30.0) -> str:
    return create_proxy(upstream_url, 'socks5', connect_timeout=connect_timeout, idle_timeout=idle_timeout,
                        timeout=timeout)


def cleanup():
    """清理所有代理资源。

    通常不需要手动调用,进程结束时会自动清理。
    仅在长期运行的服务中需要手动清理时使用。
    """
    with _registry_lock:
        proxies = list(_proxy_registry.values())
        _proxy_registry.clear()

    for proxy in proxies:
        try:
            _run_async(proxy.stop(), timeout=10.0)
        except Exception:
            pass


atexit.register(cleanup)

__all__ = [
    'create_proxy',
    'create_http_proxy',
    'create_socks5_proxy',
    'create_proxy_async',
    'create_http_proxy_async',
    'create_socks5_proxy_async',
    'cleanup',
    'HttpProxy',
    'Socks5Proxy',
    'BaseProxy',
    'ProxyManager',
    'ProxyError',
    'UpstreamConnectionError',
    'ClientConnectionError'
]
