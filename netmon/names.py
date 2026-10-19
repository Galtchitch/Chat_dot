"""Определение имён узлов: обратный DNS и NetBIOS (Windows)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import re
import shutil
import socket

from .checks import run_command

log = logging.getLogger("netmon.names")

SYSTEM = platform.system().lower()
NBTSTAT = shutil.which("nbtstat")

#: Строка вида ``SERVER01       <00>  UNIQUE      Registered``
_NETBIOS_RE = re.compile(r"^\s*(\S+)\s+<00>\s+UNIQUE", re.IGNORECASE | re.MULTILINE)

_cache: dict[str, str] = {}


def short_name(value: str) -> str:
    """Отбросить домен и завершающую точку: ``server01.corp.local`` → ``server01``."""
    name = (value or "").strip().rstrip(".")
    return name.split(".")[0] if name else ""


def is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def parse_nbtstat(output: str) -> str:
    """Извлечь имя компьютера из вывода ``nbtstat -A``."""
    for match in _NETBIOS_RE.finditer(output or ""):
        candidate = match.group(1).strip()
        if candidate and not candidate.startswith("__"):
            return short_name(candidate)
    return ""


def _reverse_dns(address: str) -> str:
    try:
        name = socket.gethostbyaddr(address)[0]
    except OSError:
        return ""
    return short_name(name)


async def _netbios(address: str, timeout: float) -> str:
    if SYSTEM != "windows" or NBTSTAT is None or not is_address(address):
        return ""
    outcome = await run_command([NBTSTAT, "-A", address], max(timeout, 2.0))
    if outcome is None:
        return ""
    _code, output = outcome
    return parse_nbtstat(output)


async def resolve(address: str, timeout: float = 2.0) -> str:
    """Имя узла: сначала обратный DNS, затем NetBIOS.

    Возвращает пустую строку, если имя определить не удалось.
    """
    address = address.strip()
    if not address:
        return ""
    cached = _cache.get(address)
    if cached:
        return cached

    try:
        name = await asyncio.wait_for(asyncio.to_thread(_reverse_dns, address), timeout)
    except asyncio.TimeoutError:
        name = ""
    if not name:
        name = await _netbios(address, timeout)

    if name:
        _cache[address] = name
    return name


async def resolve_many(
    addresses: list[str], workers: int = 16, timeout: float = 2.0
) -> dict[str, str]:
    """Определить имена сразу для нескольких адресов."""
    semaphore = asyncio.Semaphore(max(1, workers))
    result: dict[str, str] = {}

    async def one(address: str) -> None:
        async with semaphore:
            result[address] = await resolve(address, timeout)

    await asyncio.gather(*(one(address) for address in addresses))
    return result
