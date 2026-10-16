"""Модели предметной области."""

from __future__ import annotations

from dataclasses import dataclass

#: Поддерживаемые типы проверок.
KINDS = ("icmp", "tcp", "http")


@dataclass
class Host:
    """Один проверяемый узел сети."""

    name: str
    address: str
    kind: str = "icmp"
    port: int | None = None
    interval: int | None = None
    timeout: float | None = None
    enabled: bool = True
    #: Имя сети из config.yaml (может быть пустым).
    network: str = ""

    # Последнее известное состояние. Хранится в БД, чтобы после перезапуска
    # бот не рассылал оповещения заново и продолжал напоминания.
    ok: bool | None = None
    consecutive_failures: int = 0
    changed_at: float | None = None
    last_notified: float | None = None
    latency: float | None = None
    detail: str = ""

    @property
    def target(self) -> str:
        """Человекочитаемая цель проверки, например ``nas:445``."""
        if self.port and self.kind in ("tcp", "http"):
            return f"{self.address}:{self.port}"
        return self.address
