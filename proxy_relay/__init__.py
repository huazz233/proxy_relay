#!/usr/bin/env python3
"""多协议代理中转器 - 支持HTTP/HTTPS/SOCKS5/SOCKS5H协议互转，本地代理无需账密认证"""

import asyncio
import base64
import logging
import socket
import struct
import sys
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse

__version__ = "1.0.0"
__author__ = "huazz233"

logger = logging.getLogger(__name__)


# 工具函数

def find_free_port() -> int:
    """获取空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        return s.getsockname()[1]


def parse_proxy_url(url: str) -> Dict[str, Any]:
    """解析代理URL"""
    parsed = urlparse(url)
    return {
        'scheme': parsed.scheme.lower(),
        'host': parsed.hostname,
        'port': parsed.port,
        'username': parsed.username,
        'password': parsed.password
    }


def validate_proxy_config(config: Dict[str, Any]) -> bool:
    """验证代理配置"""
    required_fields = ['scheme', 'host', 'port']
    
    for field in required_fields:
        if field not in config or config[field] is None:
            logger.error(f"代理配置缺少必需字段: {field}")
            return False
    
    supported_schemes = ['http', 'https', 'socks5', 'socks5h']
    if config['scheme'] not in supported_schemes:
        logger.error(f"不支持的代理协议: {config['scheme']}")
        return False
    
    if not (1 <= config['port'] <= 65535):
        logger.error(f"无效的端口号: {config['port']}")
        return False
    
    return True


def is_socks_scheme(scheme: str) -> bool:
    """判断是否为SOCKS协议"""
    return scheme.lower() in ['socks5', 'socks5h']


# 异常类

class ProxyError(Exception):
    """代理异常"""
    pass


class UpstreamConnectionError(ProxyError):
    """上游连接异常"""
    pass


class ClientConnectionError(ProxyError):
    """客户端连接异常"""
    pass


# 辅助函数

async def connect_upstream(host: str, port: int, timeout: Optional[float] = None):
    """连接上游代理"""
    try:
        if timeout:
            return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return await asyncio.open_connection(host, port)
    except asyncio.TimeoutError:
        raise UpstreamConnectionError(f"连接超时 {host}:{port}")
    except Exception as e:
        raise UpstreamConnectionError(f"连接失败 {host}:{port} - {e}")


async def send_http_connect(upstream_reader, upstream_writer, target_host: str, target_port: int, auth_config: dict = None) -> bool:
    """发送HTTP CONNECT请求"""
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
    
    if auth_config and auth_config.get('username') and auth_config.get('password'):
        auth_str = f"{auth_config['username']}:{auth_config['password']}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        request += f"Proxy-Authorization: Basic {auth_header}\r\n"
    
    request += "\r\n"
    upstream_writer.write(request.encode())
    await upstream_writer.drain()

    response_line = await upstream_reader.readline()
    if not response_line:
        raise UpstreamConnectionError("上游无响应")

    response = response_line.decode('utf-8', errors='ignore').strip()

    while True:
        line = await upstream_reader.readline()
        if not line or line == b'\r\n':
            break

    if "200" not in response:
        raise UpstreamConnectionError(f"CONNECT失败: {response}")

    return True


# 基类

class BaseProxy(ABC):
    """代理基类"""

    def __init__(self, upstream_url: str, connect_timeout: Optional[float] = 30.0, idle_timeout: Optional[float] = 300.0):
        self.upstream_config = parse_proxy_url(upstream_url)

        if not validate_proxy_config(self.upstream_config):
            raise ValueError(f"无效的上游代理配置: {upstream_url}")

        self.local_port = find_free_port()
        self.local_host = '127.0.0.1'
        self.running = False
        self._server_thread = None
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout

    def start(self) -> str:
        if self.running:
            return self.get_local_url()

        self.running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()
        time.sleep(0.5)

        logger.info(f"代理启动: {self.get_local_url()}")
        return self.get_local_url()

    def stop(self):
        if not self.running:
            return
        self.running = False
        logger.info("代理停止")

    def _run_server(self):
        try:
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._async_server())
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"服务器出错: {e}")
            self.running = False

    async def _async_server(self):
        server = await asyncio.start_server(
            self._handle_client,
            self.local_host,
            self.local_port
        )

        async with server:
            await server.serve_forever()

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

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.get_local_url()})"

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}("
                f"upstream={self.upstream_config['scheme']}://{self.upstream_config['host']}:{self.upstream_config['port']}, "
                f"local={self.get_local_url()}, "
                f"running={self.running})")


# HTTP代理实现

class HttpProxy(BaseProxy):
    """HTTP代理"""

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

        except Exception as e:
            logger.error(f"HTTP客户端出错: {e}")
            try:
                writer.write(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
                await writer.drain()
            except:
                pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except:
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
                upstream_reader, upstream_writer, target_host, target_port, self.upstream_config
            )

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # 跳过客户端请求头
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n':
                    break

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception as e:
            logger.error(f"CONNECT出错: {e}")
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except:
                pass

    async def _handle_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                   request_line: bytes):
        try:
            upstream_reader, upstream_writer = await connect_upstream(
                self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
            )

            upstream_writer.write(request_line)

            auth_added = False
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    if not auth_added and self.upstream_config.get('username') and self.upstream_config.get('password'):
                        auth_str = f"{self.upstream_config['username']}:{self.upstream_config['password']}"
                        auth_header = base64.b64encode(auth_str.encode()).decode()
                        upstream_writer.write(f"Proxy-Authorization: Basic {auth_header}\r\n".encode())
                    upstream_writer.write(line)
                    break

                if line.lower().startswith(b'proxy-authorization:'):
                    auth_added = True

                upstream_writer.write(line)

            await upstream_writer.drain()
            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception as e:
            logger.error(f"HTTP请求出错: {e}")
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except:
                pass


# SOCKS5代理实现

class Socks5Proxy(BaseProxy):
    """SOCKS5代理,支持双协议"""

    def get_local_url(self) -> str:
        return f"socks5://{self.local_host}:{self.local_port}"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            initial_data = await reader.readexactly(1)

            if initial_data and initial_data[0] == 0x05:
                await self._handle_socks5(reader, writer, initial_data)
            else:
                await self._handle_http(reader, writer, initial_data)

        except Exception as e:
            logger.error(f"客户端出错: {e}")
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except:
                pass

    async def _handle_socks5(self, reader, writer, initial_data):
        try:
            if initial_data[0] != 0x05:
                return

            nmethods = (await reader.readexactly(1))[0]
            await reader.readexactly(nmethods)

            writer.write(b'\x05\x00')
            await writer.drain()

            ver, cmd, _, atyp = await reader.readexactly(4)

            if ver != 0x05 or cmd != 0x01:
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            target_host, target_port = await self._parse_address(reader, atyp)
            if not target_host:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            upstream_reader, upstream_writer = await self._connect_upstream(target_host, target_port)

            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception as e:
            logger.error(f"SOCKS5出错: {e}")
            try:
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
            except:
                pass

    async def _handle_http(self, reader, writer, initial_data):
        try:
            request_line_bytes = initial_data + await reader.readline()
            request_line = request_line_bytes.decode('utf-8', errors='ignore').strip()
            parts = request_line.split()

            if len(parts) < 3 or parts[0].upper() != 'CONNECT':
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            target_host, target_port_str = parts[1].split(':', 1)
            target_port = int(target_port_str)

            # 跳过请求头
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n':
                    break

            upstream_reader, upstream_writer = await self._connect_upstream(target_host, target_port)

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            await self._relay_data(reader, writer, upstream_reader, upstream_writer)

        except Exception as e:
            logger.error(f"HTTP出错: {e}")
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except:
                pass

    async def _parse_address(self, reader, atyp: int) -> Tuple[str, int]:
        try:
            if atyp == 0x01:  # IPv4
                addr_bytes = await reader.readexactly(4)
                target_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # 域名
                addr_len = (await reader.readexactly(1))[0]
                target_host = (await reader.readexactly(addr_len)).decode('ascii')
            elif atyp == 0x04:  # IPv6
                addr_bytes = await reader.readexactly(16)
                target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                return None, None

            target_port = struct.unpack('>H', await reader.readexactly(2))[0]
            return target_host, target_port
        except Exception:
            return None, None

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
        await send_http_connect(upstream_reader, upstream_writer, target_host, target_port, self.upstream_config)
        return upstream_reader, upstream_writer

    async def _connect_socks5(self, target_host: str, target_port: int):
        upstream_reader, upstream_writer = await connect_upstream(
            self.upstream_config['host'], self.upstream_config['port'], self.connect_timeout
        )

        # 握手
        auth_methods = [0x00]
        if self.upstream_config.get('username') and self.upstream_config.get('password'):
            auth_methods.append(0x02)

        upstream_writer.write(b'\x05' + bytes([len(auth_methods)]) + bytes(auth_methods))
        await upstream_writer.drain()

        ver, chosen_method = await upstream_reader.readexactly(2)
        if ver != 0x05 or chosen_method == 0xFF:
            raise UpstreamConnectionError("SOCKS5握手失败")

        # 认证
        if chosen_method == 0x02:
            username = self.upstream_config['username'].encode('utf-8')
            password = self.upstream_config['password'].encode('utf-8')
            upstream_writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
            await upstream_writer.drain()

            ver, status = await upstream_reader.readexactly(2)
            if ver != 0x01 or status != 0x00:
                raise UpstreamConnectionError("SOCKS5认证失败")

        # 连接请求
        req = bytearray(b'\x05\x01\x00')

        try:
            if hasattr(socket, 'inet_pton'):
                ip_bytes = socket.inet_pton(socket.AF_INET, target_host)
                req.append(0x01)
                req.extend(ip_bytes)
            else:
                ip_bytes = socket.inet_aton(target_host)
                req.append(0x01)
                req.extend(ip_bytes)
        except (socket.error, OSError):
            try:
                if hasattr(socket, 'inet_pton'):
                    ip_bytes = socket.inet_pton(socket.AF_INET6, target_host)
                    req.append(0x04)
                    req.extend(ip_bytes)
                else:
                    raise socket.error("IPv6 not supported")
            except (socket.error, OSError):
                req.append(0x03)
                req.append(len(target_host))
                req.extend(target_host.encode('ascii'))

        req.extend(target_port.to_bytes(2, 'big'))
        upstream_writer.write(req)
        await upstream_writer.drain()

        response = await upstream_reader.readexactly(10)
        if response[1] != 0x00:
            raise UpstreamConnectionError(f"SOCKS5连接失败: {response[1]}")

        return upstream_reader, upstream_writer


# 公共API

def create_proxy(upstream_url: str, local_type: str = 'http', connect_timeout: float = 30.0, idle_timeout: float = 300.0) -> str:
    """创建代理并返回本地URL"""
    if not upstream_url:
        raise ValueError("上游代理URL不能为空")

    if local_type not in ['http', 'socks5']:
        raise ValueError(f"不支持的本地代理类型: {local_type}")

    try:
        upstream_config = parse_proxy_url(upstream_url)
    except Exception as e:
        raise ValueError(f"解析上游代理URL失败: {e}")

    if not validate_proxy_config(upstream_config):
        raise ValueError(f"无效的上游代理配置: {upstream_url}")

    try:
        if local_type == 'http':
            proxy = HttpProxy(upstream_url, connect_timeout=connect_timeout, idle_timeout=idle_timeout)
        elif local_type == 'socks5':
            proxy = Socks5Proxy(upstream_url, connect_timeout=connect_timeout, idle_timeout=idle_timeout)
        else:
            raise ValueError(f"未处理的本地代理类型: {local_type}")

        local_url = proxy.start()
        logger.debug(f"代理创建成功: {upstream_url} -> {local_url}")
        return local_url

    except Exception as e:
        logger.error(f"创建代理失败: {e}")
        raise ProxyError(f"创建代理失败: {e}")


def create_http_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0) -> str:
    """创建HTTP本地代理"""
    return create_proxy(upstream_url, 'http', connect_timeout=connect_timeout, idle_timeout=idle_timeout)


def create_socks5_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0) -> str:
    """创建SOCKS5本地代理"""
    return create_proxy(upstream_url, 'socks5', connect_timeout=connect_timeout, idle_timeout=idle_timeout)


def get_supported_protocols() -> dict:
    """返回支持的协议组合"""
    return {
        "upstream_protocols": ["http", "https", "socks5", "socks5h"],
        "local_protocols": ["http", "socks5"],
        "combinations": [
            {"upstream": "http", "local": "http", "description": "HTTP上游 → HTTP本地"},
            {"upstream": "http", "local": "socks5", "description": "HTTP上游 → SOCKS5本地"},
            {"upstream": "https", "local": "http", "description": "HTTPS上游 → HTTP本地"},
            {"upstream": "https", "local": "socks5", "description": "HTTPS上游 → SOCKS5本地"},
            {"upstream": "socks5", "local": "http", "description": "SOCKS5上游 → HTTP本地"},
            {"upstream": "socks5", "local": "socks5", "description": "SOCKS5上游 → SOCKS5本地"},
            {"upstream": "socks5h", "local": "http", "description": "SOCKS5H上游 → HTTP本地"},
            {"upstream": "socks5h", "local": "socks5", "description": "SOCKS5H上游 → SOCKS5本地"},
        ]
    }


def get_version_info() -> dict:
    """返回版本信息"""
    return {
        "version": __version__,
        "author": __author__,
        "description": "多协议代理中转器，支持HTTP/HTTPS/SOCKS5/SOCKS5H协议互转"
    }


__all__ = [
    'create_proxy',
    'create_http_proxy',
    'create_socks5_proxy',
    'get_supported_protocols',
    'get_version_info',
    'HttpProxy',
    'Socks5Proxy',
    'BaseProxy',
    'ProxyError',
    'UpstreamConnectionError',
    'ClientConnectionError'
]

