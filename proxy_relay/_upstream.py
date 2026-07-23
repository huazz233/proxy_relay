"""Adapters for configured upstream proxy types."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional

from ._protocol import is_socks_scheme, send_http_connect, send_socks5_connect
from ._transport import UpstreamTunnel, close_writer, connect_upstream

TrackWriter = Optional[Callable[[Any], None]]


class UpstreamConnector(ABC):
    """Connect local proxy handlers to the configured upstream proxy."""

    @abstractmethod
    async def connect(self, target_host: str, target_port: int) -> UpstreamTunnel:
        pass


class HttpUpstreamConnector(UpstreamConnector):
    def __init__(self, upstream_config: Dict[str, Any], connect_timeout: Optional[float],
                 track_writer: TrackWriter = None,
                 untrack_writer: TrackWriter = None):
        self.upstream_config = upstream_config
        self.connect_timeout = connect_timeout
        self.track_writer = track_writer
        self.untrack_writer = untrack_writer

    async def open_proxy_stream(self) -> UpstreamTunnel:
        use_tls = self.upstream_config['scheme'] == 'https'
        reader, writer = await connect_upstream(
            self.upstream_config['host'],
            self.upstream_config['port'],
            self.connect_timeout,
            use_tls=use_tls,
            server_hostname=self.upstream_config['host'],
        )
        if self.track_writer is not None:
            self.track_writer(writer)
        return UpstreamTunnel(reader, writer)

    async def connect(self, target_host: str, target_port: int) -> UpstreamTunnel:
        tunnel = await self.open_proxy_stream()
        try:
            await send_http_connect(
                tunnel.reader,
                tunnel.writer,
                target_host,
                target_port,
                self.upstream_config,
                self.connect_timeout,
            )
            return tunnel
        except Exception:
            if self.untrack_writer is not None:
                self.untrack_writer(tunnel.writer)
            await close_writer(tunnel.writer)
            raise


class Socks5UpstreamConnector(UpstreamConnector):
    def __init__(self, upstream_config: Dict[str, Any], connect_timeout: Optional[float],
                 track_writer: TrackWriter = None,
                 untrack_writer: TrackWriter = None):
        self.upstream_config = upstream_config
        self.connect_timeout = connect_timeout
        self.track_writer = track_writer
        self.untrack_writer = untrack_writer

    async def connect(self, target_host: str, target_port: int) -> UpstreamTunnel:
        reader, writer = await connect_upstream(
            self.upstream_config['host'],
            self.upstream_config['port'],
            self.connect_timeout,
        )
        if self.track_writer is not None:
            self.track_writer(writer)
        tunnel = UpstreamTunnel(reader, writer)
        try:
            await send_socks5_connect(
                tunnel.reader,
                tunnel.writer,
                target_host,
                target_port,
                self.upstream_config,
                self.connect_timeout,
            )
            return tunnel
        except Exception:
            if self.untrack_writer is not None:
                self.untrack_writer(tunnel.writer)
            await close_writer(tunnel.writer)
            raise


def create_upstream_connector(upstream_config: Dict[str, Any],
                              connect_timeout: Optional[float],
                              track_writer: TrackWriter = None,
                              untrack_writer: TrackWriter = None) -> UpstreamConnector:
    if is_socks_scheme(upstream_config['scheme']):
        return Socks5UpstreamConnector(
            upstream_config, connect_timeout,
            track_writer=track_writer, untrack_writer=untrack_writer,
        )
    return HttpUpstreamConnector(
        upstream_config, connect_timeout,
        track_writer=track_writer, untrack_writer=untrack_writer,
    )
