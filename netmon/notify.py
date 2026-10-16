"""Рассылка уведомлений: окно тишины и ночная сводка."""

from __future__ import annotations

import html
import logging

from telegram.error import Forbidden, TelegramError

from .monitor import Event
from .schedule import Clock
from .storage import Storage

log = logging.getLogger("netmon.notify")

EMOJI = {"down": "🔴", "up": "🟢", "still_down": "⏱️"}
TITLES = {"down": "недоступен", "up": "снова доступен", "still_down": "всё ещё недоступен"}


def format_event(event: Event, clock: Clock) -> str:
    """Текст одного оповещения."""
    host = event.host
    lines = [
        f"{EMOJI.get(event.kind, '•')} <b>{html.escape(host.name)}</b> {TITLES.get(event.kind, '')}".rstrip(),
        f"Адрес: <code>{html.escape(host.target)}</code>",
        f"Проверка: {host.kind}",
    ]
    if event.result.ok and event.result.latency_ms is not None:
        lines.append(f"Отклик: {event.result.latency_ms:.0f} мс")
    if not event.result.ok and event.result.detail:
        lines.append(f"Причина: {html.escape(event.result.detail)}")
    if event.kind == "still_down" and host.changed_at:
        lines.append(f"Недоступен с: {clock.label(host.changed_at)}")
    lines.append(f"Время: {clock.label(event.at)}")
    return "\n".join(lines)


class Notifier:
    """Отправляет события подписчикам с учётом окна тишины.

    Вне окна события копятся в базе, а в начале окна уходит сводка.
    """

    def __init__(self, app, storage: Storage, clock: Clock) -> None:
        self.app = app
        self.storage = storage
        self.clock = clock

    async def __call__(self, event: Event) -> None:
        if self.clock.is_open(event.at):
            await self.broadcast(format_event(event, self.clock))
            return
        if event.kind == "still_down":
            # Напоминания ночью не копим, иначе сводка разрастётся.
            return
        self.storage.add_outbox(
            event.at, event.host.name, event.kind, event.result.detail or ""
        )
        log.info("Событие %s (%s) отложено до %s", event.kind, event.host.name, self.clock.describe())

    async def tick(self, at: float | None = None) -> None:
        """Вызывается из цикла мониторинга: отправить накопленное, если окно открыто."""
        if not self.clock.is_open(at):
            return
        pending = self.storage.list_outbox()
        if not pending:
            return
        self.storage.remove_outbox([item[0] for item in pending])
        await self.broadcast(self._digest(pending))

    async def broadcast(self, text: str) -> None:
        for chat_id, _notify in self.storage.list_subscribers(notify_only=True):
            try:
                await self.app.bot.send_message(chat_id, text)
            except Forbidden:
                log.warning("Чат %s заблокировал бота — отключаю оповещения", chat_id)
                self.storage.set_notify(chat_id, False)
            except TelegramError as exc:
                log.warning("Не удалось отправить сообщение в чат %s: %s", chat_id, exc)

    def _digest(self, pending: list[tuple]) -> str:
        lines = [f"🌙 Сводка за время тишины ({self.clock.describe()}) — событий: {len(pending)}"]
        for _id, at, name, kind, _detail in pending:
            emoji = EMOJI.get(kind, "•")
            title = TITLES.get(kind, kind)
            lines.append(f"{emoji} {self.clock.time_label(at)} <b>{html.escape(name)}</b> — {title}")

        down = [host for host in self.storage.list_hosts() if host.ok is False]
        if down:
            names = ", ".join(html.escape(host.name) for host in down[:20])
            tail = f" и ещё {len(down) - 20}" if len(down) > 20 else ""
            lines.append(f"\nСейчас недоступны ({len(down)}): {names}{tail}")
        else:
            lines.append("\nСейчас все узлы доступны.")
        return "\n".join(lines)
