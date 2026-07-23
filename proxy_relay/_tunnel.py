"""Runtime for active client/upstream byte tunnels."""

import asyncio
import contextlib
import logging
import time
from typing import List, Optional, Set

from ._transport import DEFAULT_CLOSE_TIMEOUT, RELAY_CHUNK_SIZE, close_writer, close_writer_now


class TunnelRuntime:
    """Own active tunnel writers and pump tasks for deterministic shutdown."""

    def __init__(self, idle_timeout: Optional[float],
                 close_timeout: float = DEFAULT_CLOSE_TIMEOUT,
                 logger: Optional[logging.Logger] = None) -> None:
        self.idle_timeout = idle_timeout
        self.close_timeout = close_timeout
        self.logger = logger or logging.getLogger(__name__)
        self._writers: Set[asyncio.StreamWriter] = set()
        self._tasks: Set[asyncio.Task] = set()
        self._closing = False

    def reopen(self) -> None:
        self._closing = False

    def track_writer(self, writer: Optional[asyncio.StreamWriter]) -> None:
        if writer is None:
            return
        if self._closing:
            close_writer_now(writer)
            return
        self._writers.add(writer)

    def untrack_writer(self, writer: Optional[asyncio.StreamWriter]) -> None:
        if writer is not None:
            self._writers.discard(writer)

    def track_task(self, task: Optional[asyncio.Task]) -> None:
        if task is not None and not self._closing:
            self._tasks.add(task)

    def untrack_task(self, task: Optional[asyncio.Task]) -> None:
        if task is not None:
            self._tasks.discard(task)

    async def close_one(self, writer: Optional[asyncio.StreamWriter]) -> None:
        self.untrack_writer(writer)
        await close_writer(writer, timeout=self.close_timeout)

    async def close_all(self) -> None:
        self._closing = True
        current_task = asyncio.current_task()
        tasks = tuple(task for task in self._tasks if task is not current_task)
        writers = tuple(self._writers)

        for task in tasks:
            task.cancel()
        for writer in writers:
            close_writer_now(writer)

        await asyncio.gather(
            *(close_writer(writer, timeout=self.close_timeout) for writer in writers),
            return_exceptions=True,
        )

        if tasks:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.close_timeout,
                )

        for task in tasks:
            self._tasks.discard(task)
        for writer in writers:
            self._writers.discard(writer)

    async def relay(self,
                    client_reader: asyncio.StreamReader,
                    client_writer: asyncio.StreamWriter,
                    upstream_reader: asyncio.StreamReader,
                    upstream_writer: asyncio.StreamWriter) -> None:
        self.track_writer(client_writer)
        self.track_writer(upstream_writer)

        last_activity: List[float] = [time.monotonic()]

        pump_client = asyncio.create_task(
            self._copy_data("client->upstream", client_reader, upstream_writer, last_activity)
        )
        pump_upstream = asyncio.create_task(
            self._copy_data("upstream->client", upstream_reader, client_writer, last_activity)
        )
        pumps = {pump_client, pump_upstream}

        watchdog: Optional[asyncio.Task] = None
        if self.idle_timeout is not None:
            watchdog = asyncio.create_task(self._idle_watchdog(last_activity, self.idle_timeout))

        all_tasks = set(pumps)
        if watchdog is not None:
            all_tasks.add(watchdog)
        self._tasks.update(all_tasks)

        try:
            # Half-close friendly: keep going until both pumps finish, unless
            # the connection-level idle watchdog fires first.
            pending = set(all_tasks)
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED,
                )
                if watchdog is not None and watchdog in done:
                    for task in pumps:
                        if not task.done():
                            task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    break
                # A pump finished; if the other is still running, loop and wait.
                # Drop finished pump(s) from the "still needed" set implicitly
                # via pending. When both pumps are done, cancel watchdog.
                if all(task.done() for task in pumps):
                    if watchdog is not None and not watchdog.done():
                        watchdog.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await watchdog
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    break

            for task in pumps:
                if task.done():
                    with contextlib.suppress(asyncio.CancelledError):
                        exc = task.exception()
                        if exc is not None:
                            self.logger.debug("Relay task ended with exception: %r", exc)
        finally:
            for task in all_tasks:
                if not task.done():
                    task.cancel()
                self._tasks.discard(task)
            await asyncio.gather(*all_tasks, return_exceptions=True)
            await asyncio.gather(
                self.close_one(client_writer),
                self.close_one(upstream_writer),
                return_exceptions=True,
            )

    async def _idle_watchdog(self, last_activity: List[float], idle_timeout: float) -> None:
        """Fire when no direction has seen data for idle_timeout seconds."""
        interval = max(idle_timeout / 4.0, 0.25)
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - last_activity[0] >= idle_timeout:
                self.logger.debug("Relay idle timeout (connection-level)")
                return

    async def _copy_data(self,
                         direction: str,
                         src: asyncio.StreamReader,
                         dst: asyncio.StreamWriter,
                         last_activity: List[float]) -> None:
        try:
            while True:
                data = await src.read(RELAY_CHUNK_SIZE)
                if not data:
                    # Half-close: forward FIN; leave the reverse pump running.
                    if dst.can_write_eof():
                        with contextlib.suppress(Exception):
                            dst.write_eof()
                    return
                last_activity[0] = time.monotonic()
                dst.write(data)
                await dst.drain()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.debug("Relay copy failed (%s): %r", direction, exc)
