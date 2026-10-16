"""Асинхронный цикл мониторинга узлов и машина состояний оповещений."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .checks import CheckResult, check
from .config import Config
from .models import Host
from .storage import Storage

log = logging.getLogger("netmon.monitor")

#: Типы событий, о которых уведомляются подписчики.
EventKind = str  # "down" | "up" | "still_down"


@dataclass
class Event:
    host: Host
    kind: EventKind
    result: CheckResult
    at: float


Notifier = Callable[[Event], Awaitable[None]]
TickHook = Callable[[], Awaitable[None]]


class Monitor:
    """Периодически опрашивает узлы и сообщает о смене состояния."""

    def __init__(
        self,
        storage: Storage,
        config: Config,
        on_event: Notifier | None = None,
        on_tick: TickHook | None = None,
    ) -> None:
        self.storage = storage
        self.config = config
        self.on_event = on_event
        self.on_tick = on_tick
        self._stop = asyncio.Event()
        self._semaphore = asyncio.Semaphore(config.monitor.workers)
        self._next_due: dict[str, float] = {}

    def stop(self) -> None:
        self._stop.set()

    # --------------------------------------------------------------- основной

    async def run(self) -> None:
        log.info("Мониторинг запущен (интервал по умолчанию %ss)", self.config.monitor.default_interval)
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:  # noqa: BLE001 - цикл не должен падать
                log.exception("Ошибка в цикле мониторинга")
            if self.on_tick is not None:
                try:
                    await self.on_tick()
                except Exception:  # noqa: BLE001
                    log.exception("Ошибка в обработчике цикла мониторинга")
            await self._wait_next()

    async def _tick(self) -> None:
        hosts = self.storage.list_hosts(enabled_only=True)
        now = time.time()
        due = [host for host in hosts if self._next_due.get(host.name, 0.0) <= now]
        if not due:
            return
        results = await asyncio.gather(*(self._probe(host) for host in due))
        await self._apply(results)

    async def _probe(self, host: Host) -> tuple[Host, CheckResult]:
        async with self._semaphore:
            result = await check(host, self.config.monitor.timeout)
        return host, result

    async def _apply(
        self, pairs: list[tuple[Host, CheckResult]], emit: bool = True
    ) -> list[Event]:
        now = time.time()
        threshold = max(1, self.config.monitor.flap_threshold)
        repeat_minutes = self.config.monitor.down_repeat_minutes
        events: list[Event] = []

        for probed, result in pairs:
            interval = probed.interval or self.config.monitor.default_interval
            self._next_due[probed.name] = now + interval

            stored = self.storage.get_host(probed.name)
            if stored is None:  # узел удалили, пока шла проверка
                continue

            previous = stored.ok
            failures = stored.consecutive_failures
            changed_at = stored.changed_at
            last_notified = stored.last_notified
            kind: EventKind | None = None

            if result.ok:
                failures = 0
                new_ok: bool | None = True
                if previous is False:
                    kind, changed_at, last_notified = "up", now, now
                elif previous is None:
                    changed_at = now
            else:
                failures += 1
                if previous is False:
                    new_ok = False
                    base = last_notified or changed_at or now
                    if repeat_minutes and now - base >= repeat_minutes * 60:
                        kind, last_notified = "still_down", now
                elif failures >= threshold:
                    new_ok, kind, changed_at, last_notified = False, "down", now, now
                else:
                    new_ok = previous

            self.storage.update_state(
                stored.name,
                ok=new_ok,
                consecutive_failures=failures,
                latency=result.latency_ms,
                detail=result.detail,
                changed_at=changed_at,
                last_notified=last_notified,
            )

            if emit and kind:
                fresh = self.storage.get_host(stored.name)
                if fresh is not None:
                    events.append(Event(host=fresh, kind=kind, result=result, at=now))

        if emit:
            for event in events:
                await self._emit(event)
        return events

    async def _emit(self, event: Event) -> None:
        if self.on_event is None:
            return
        try:
            await self.on_event(event)
        except Exception:  # noqa: BLE001 - сбой отправки не должен ломать цикл
            log.exception("Не удалось обработать событие для %s", event.host.name)

    async def _wait_next(self) -> None:
        now = time.time()
        upcoming = [moment for moment in self._next_due.values() if moment > now]
        delay = min(upcoming) - now if upcoming else 5.0
        delay = max(0.5, min(delay, 30.0))
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    # ------------------------------------------------------- ручная проверка

    async def probe_now(self, host: Host, emit: bool = False) -> CheckResult:
        """Проверить узел немедленно (используется командами бота)."""
        pair = await self._probe(host)
        await self._apply([pair], emit=emit)
        return pair[1]
