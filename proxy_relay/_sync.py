"""Synchronous facade: background event loop + process-level registry."""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import logging
import threading
from typing import TYPE_CHECKING, Dict, Optional, Tuple

from ._errors import ProxyError

if TYPE_CHECKING:
    from ._core import BaseProxy

logger = logging.getLogger(__name__)

# Registry entry: (proxy, creating_loop_or_None)
# None means the proxy was created on the background loop (sync API).
_proxy_registry: Dict[str, Tuple["BaseProxy", Optional[asyncio.AbstractEventLoop]]] = {}
_registry_lock = threading.Lock()


class BackgroundLoopManager:
    """Manage a background asyncio event loop for sync-style APIs."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._ready = threading.Event()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """Return a running event loop, creating one in a background thread if needed."""
        with self._lock:
            if self._loop is not None and not self._loop.is_closed():
                # Loop object exists; ensure the thread is still alive.
                if self._thread is not None and self._thread.is_alive():
                    return self._loop
                # Thread died or was never started properly; rebuild.
                self._loop = None
                self._thread = None
                self._ready.clear()

            loop = asyncio.new_event_loop()
            self._loop = loop
            self._ready.clear()

            def run_loop() -> None:
                asyncio.set_event_loop(loop)
                # Signal readiness once the loop is actually spinning.
                loop.call_soon(self._ready.set)
                loop.run_forever()

            self._thread = threading.Thread(target=run_loop, daemon=True, name="proxy-relay-loop")
            self._thread.start()

        # Wait outside the lock so concurrent callers share the same startup.
        if not self._ready.wait(timeout=5.0):
            raise ProxyError("Background event loop failed to start")
        return loop

    def run(self, coro, timeout: Optional[float] = None):
        """Run *coro* on the background loop and wait for the result."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout=timeout)
        except (TimeoutError, concurrent.futures.TimeoutError):
            future.cancel()
            raise ProxyError(f"Operation timeout ({timeout}s)")

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop the background loop and join its thread, if they exist."""
        with self._lock:
            loop = self._loop
            thread = self._thread

        if loop is None:
            return

        if loop.is_closed():
            with self._lock:
                self._loop = None
                self._thread = None
                self._ready.clear()
            return

        try:
            loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:
            pass

        if thread is not None:
            thread.join(timeout)

        with self._lock:
            if not loop.is_closed() and not loop.is_running():
                loop.close()
            if loop is self._loop:
                self._loop = None
                self._thread = None
                self._ready.clear()


_loop_manager = BackgroundLoopManager()


def register_proxy(local_url: str, proxy: "BaseProxy",
                   loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
    with _registry_lock:
        _proxy_registry[local_url] = (proxy, loop)


def unregister_proxy(local_url: str) -> Optional[Tuple["BaseProxy", Optional[asyncio.AbstractEventLoop]]]:
    with _registry_lock:
        return _proxy_registry.pop(local_url, None)


async def unregister_and_stop_async(local_url: str) -> None:
    entry = unregister_proxy(local_url)
    if entry is None:
        return
    proxy, _loop = entry
    await proxy.stop()


def stop_proxy(local_url: str, timeout: float = 10.0) -> None:
    """Stop a single proxy created via the sync or async factory APIs."""
    entry = unregister_proxy(local_url)
    if entry is None:
        return
    proxy, creating_loop = entry
    try:
        if creating_loop is None:
            # Created on the background loop (sync API).
            _loop_manager.run(proxy.stop(), timeout=timeout)
        else:
            # Created on a user loop. Prefer scheduling on that loop if it
            # is still running; otherwise best-effort close is skipped to
            # avoid cross-loop RuntimeError.
            if creating_loop.is_closed() or not creating_loop.is_running():
                logger.debug(
                    "Skipping stop for %s: creating loop is not running", local_url,
                )
                return
            future = asyncio.run_coroutine_threadsafe(proxy.stop(), creating_loop)
            try:
                future.result(timeout=timeout)
            except (TimeoutError, concurrent.futures.TimeoutError):
                future.cancel()
                raise ProxyError(f"Operation timeout ({timeout}s)")
    except ProxyError:
        raise
    except Exception as exc:
        logger.warning("Error stopping proxy %s: %r", local_url, exc)


def create_proxy(upstream_url: str, local_type: str = 'http', connect_timeout: float = 30.0,
                 idle_timeout: float = 300.0, timeout: float = 30.0) -> str:
    from ._core import _create_proxy_instance

    async def _create():
        proxy = _create_proxy_instance(upstream_url, local_type, connect_timeout, idle_timeout)
        local_url = await proxy.start()
        # None loop marker => owned by the background loop.
        register_proxy(local_url, proxy, loop=None)
        return local_url

    return _loop_manager.run(_create(), timeout=timeout)


def create_http_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0,
                      timeout: float = 30.0) -> str:
    return create_proxy(upstream_url, 'http', connect_timeout=connect_timeout,
                        idle_timeout=idle_timeout, timeout=timeout)


def create_socks5_proxy(upstream_url: str, connect_timeout: float = 30.0, idle_timeout: float = 300.0,
                        timeout: float = 30.0) -> str:
    return create_proxy(upstream_url, 'socks5', connect_timeout=connect_timeout,
                        idle_timeout=idle_timeout, timeout=timeout)


def cleanup() -> None:
    """Cleanup all proxy resources registered via factory APIs.

    Proxies created on the background loop (sync API) are stopped there.
    Proxies created on a user event loop (async API) are only stopped if
    that loop is still running; otherwise they are dropped from the
    registry to avoid cross-loop RuntimeError.
    """
    with _registry_lock:
        entries = list(_proxy_registry.items())
        _proxy_registry.clear()

    for local_url, (proxy, creating_loop) in entries:
        try:
            if creating_loop is None:
                _loop_manager.run(proxy.stop(), timeout=10.0)
            elif not creating_loop.is_closed() and creating_loop.is_running():
                future = asyncio.run_coroutine_threadsafe(proxy.stop(), creating_loop)
                try:
                    future.result(timeout=10.0)
                except (TimeoutError, concurrent.futures.TimeoutError):
                    future.cancel()
                    logger.debug("Timed out stopping async proxy %s during cleanup", local_url)
            else:
                logger.debug(
                    "Dropping proxy %s during cleanup: creating loop not running", local_url,
                )
        except Exception as exc:
            logger.debug("Error stopping proxy %s during cleanup: %r", local_url, exc)

    try:
        _loop_manager.shutdown()
    except Exception as exc:
        logger.debug("Error shutting down background loop: %r", exc)


atexit.register(cleanup)
