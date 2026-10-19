"""Загрузка конфигурации из YAML + переменных окружения и .env."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = "config.yaml"
DEFAULT_DATABASE = "data/netmon.sqlite3"


@dataclass
class TelegramConfig:
    token: str = ""
    api_base: str = ""
    admin_ids: tuple[int, ...] = ()
    #: Путь к PEM-набору доверенных ЦС или "auto" для сборки из хранилища системы.
    ca_bundle: str = ""


@dataclass
class MonitorConfig:
    default_interval: int = 60
    timeout: float = 3.0
    workers: int = 32
    flap_threshold: int = 2
    down_repeat_minutes: int = 30


@dataclass
class NotifyConfig:
    #: Окно уведомлений, например "07:00-22:30". Пусто — круглосуточно.
    window: str = "07:00-22:30"
    #: Часовой пояс IANA (например, Europe/Moscow). Пусто — время сервера.
    timezone: str = ""


@dataclass
class ScanConfig:
    timeout: float = 1.0
    workers: int = 256
    max_hosts: int = 4096


@dataclass
class NetworkConfig:
    name: str
    cidr: str


@dataclass
class Config:
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    networks: list[NetworkConfig] = field(default_factory=list)
    database: str = DEFAULT_DATABASE
    seed_hosts: list[dict[str, Any]] = field(default_factory=list)


def load_dotenv(path: str | Path = ".env") -> None:
    """Минимальный загрузчик .env без внешних зависимостей."""
    file = Path(path)
    if not file.is_file():
        return
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _int_tuple(values: Any) -> tuple[int, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        values = [part for part in values.replace(";", ",").split(",") if part.strip()]
    try:
        return tuple(int(value) for value in values)
    except (TypeError, ValueError):
        return ()


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _as_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _parse_networks(raw: Any) -> list[NetworkConfig]:
    networks: list[NetworkConfig] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        cidr = str(item.get("cidr") or "").strip()
        if not name or not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректная подсеть для сети {name!r}: {cidr!r}") from exc
        networks.append(NetworkConfig(name=name, cidr=cidr))
    return networks


def load_config(path: str | Path | None = None) -> Config:
    """Собрать конфигурацию: файл YAML, поверх него — переменные окружения."""
    load_dotenv()

    config_path = Path(path or os.environ.get("NETMON_CONFIG") or DEFAULT_CONFIG_PATH)
    raw: dict[str, Any] = {}
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Некорректный формат файла конфигурации: {config_path}")

    tg_raw = raw.get("telegram") or {}
    mon_raw = raw.get("monitor") or {}
    notify_raw = raw.get("notify") or {}
    scan_raw = raw.get("scan") or {}

    telegram = TelegramConfig(
        token=os.environ.get("TELEGRAM_BOT_TOKEN") or str(tg_raw.get("token") or ""),
        api_base=str(tg_raw.get("api_base") or "").strip(),
        admin_ids=_int_tuple(os.environ.get("NETMON_ADMIN_IDS") or tg_raw.get("admin_ids")),
        ca_bundle=str(os.environ.get("NETMON_CA_BUNDLE") or tg_raw.get("ca_bundle") or "").strip(),
    )

    monitor = MonitorConfig(
        default_interval=max(5, _as_int(mon_raw.get("default_interval"), 60)),
        timeout=max(0.5, _as_float(mon_raw.get("timeout"), 3.0)),
        workers=max(1, _as_int(mon_raw.get("workers"), 32)),
        flap_threshold=max(1, _as_int(mon_raw.get("flap_threshold"), 2)),
        down_repeat_minutes=max(0, _as_int(mon_raw.get("down_repeat_minutes"), 30)),
    )

    notify = NotifyConfig(
        window=str(notify_raw.get("window", "07:00-22:30")),
        timezone=str(notify_raw.get("timezone") or "").strip(),
    )

    scan = ScanConfig(
        timeout=max(0.2, _as_float(scan_raw.get("timeout"), 1.0)),
        workers=max(1, _as_int(scan_raw.get("workers"), 256)),
        max_hosts=max(1, _as_int(scan_raw.get("max_hosts"), 4096)),
    )

    seed_hosts = [item for item in (raw.get("hosts") or []) if isinstance(item, dict)]

    return Config(
        telegram=telegram,
        monitor=monitor,
        notify=notify,
        scan=scan,
        networks=_parse_networks(raw.get("networks")),
        database=str(raw.get("database") or DEFAULT_DATABASE),
        seed_hosts=seed_hosts,
    )
