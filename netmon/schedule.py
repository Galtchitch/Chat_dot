"""Расписание уведомлений: окно тишины и часовой пояс."""

from __future__ import annotations

import time
from datetime import datetime, tzinfo

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - запасной вариант для очень старых сборок
    ZoneInfo = None  # type: ignore[assignment]

#: Значения, означающие «уведомлять круглосуточно».
ALWAYS = ("", "always", "all", "24h", "24/7", "*")


def _parse_clock(value: str) -> int:
    parts = value.strip().split(":")
    if len(parts) > 2:
        raise ValueError(f"Не удалось разобрать время: {value!r}")
    try:
        hours = int(parts[0])
        minutes = int(parts[1]) if len(parts) > 1 else 0
    except ValueError as exc:
        raise ValueError(f"Не удалось разобрать время: {value!r}") from exc
    if not 0 <= hours < 24 or not 0 <= minutes < 60:
        raise ValueError(f"Недопустимое время: {value!r}")
    return hours * 60 + minutes


def parse_window(value: str | None) -> tuple[int, int] | None:
    """Разобрать окно вида ``07:00-22:30``. Пустая строка — круглосуточно (None)."""
    if value is None:
        return None
    text = value.strip().lower()
    if text in ALWAYS:
        return None
    if "-" not in text:
        raise ValueError(f"Ожидается формат «ЧЧ:ММ-ЧЧ:ММ», получено: {value!r}")
    start_text, end_text = text.split("-", 1)
    return _parse_clock(start_text), _parse_clock(end_text)


def format_minutes(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def resolve_timezone(name: str) -> tzinfo | None:
    if not name:
        return None
    if ZoneInfo is None:
        raise ValueError("Поддержка часовых поясов недоступна: установите пакет tzdata.")
    return ZoneInfo(name)


class Clock:
    """Определяет, разрешены ли уведомления в текущий момент."""

    def __init__(self, window: str = "", timezone_name: str = "") -> None:
        self.window = parse_window(window)
        self.timezone = resolve_timezone(timezone_name)

    def moment(self, at: float | None = None) -> datetime:
        stamp = time.time() if at is None else at
        return datetime.fromtimestamp(stamp, self.timezone)

    def minutes(self, at: float | None = None) -> int:
        moment = self.moment(at)
        return moment.hour * 60 + moment.minute

    def is_open(self, at: float | None = None) -> bool:
        if self.window is None:
            return True
        start, end = self.window
        if start == end:
            return True
        current = self.minutes(at)
        if start < end:
            return start <= current < end
        return current >= start or current < end  # окно через полночь

    def label(self, at: float | None = None) -> str:
        return self.moment(at).strftime("%d.%m %H:%M:%S")

    def time_label(self, at: float | None = None) -> str:
        return self.moment(at).strftime("%H:%M")

    def describe(self) -> str:
        if self.window is None:
            return "круглосуточно"
        start, end = self.window
        return f"{format_minutes(start)}–{format_minutes(end)}"
