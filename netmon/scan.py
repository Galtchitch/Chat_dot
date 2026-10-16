"""Сканирование подсетей: поиск живых узлов."""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from .checks import ping
from .config import NetworkConfig

log = logging.getLogger("netmon.scan")

DEFAULT_MAX_HOSTS = 4096


def resolve_targets(
    networks: list[NetworkConfig], args: list[str]
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Сопоставить аргументы с сетями из конфигурации.

    Возвращает список ``(заголовок, CIDR, имя_сети)`` и список непонятых аргументов.
    Без аргументов берутся все сети из конфигурации.
    """
    by_name = {net.name.lower(): net for net in networks}
    targets: list[tuple[str, str, str]] = []
    unknown: list[str] = []

    if args:
        for arg in args:
            known = by_name.get(arg.lower())
            if known is not None:
                targets.append((known.name, known.cidr, known.name))
                continue
            try:
                ipaddress.ip_network(arg, strict=False)
            except ValueError:
                unknown.append(arg)
            else:
                targets.append((arg, arg, ""))
    else:
        for net in networks:
            targets.append((net.name, net.cidr, net.name))
    return targets, unknown


def _addresses(cidr: str, max_hosts: int) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    addresses: list[str] = []
    for index, address in enumerate(network.hosts()):
        if index >= max_hosts:
            break
        addresses.append(str(address))
    return addresses


async def live_hosts(
    cidr: str,
    timeout: float = 1.0,
    workers: int = 256,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> tuple[list[tuple[str, float | None]], int]:
    """Пропинговать подсеть. Возвращает живые узлы и число проверенных адресов."""
    addresses = _addresses(cidr, max_hosts)
    semaphore = asyncio.Semaphore(max(1, workers))
    live: list[tuple[str, float | None]] = []

    async def probe(address: str) -> None:
        async with semaphore:
            result = await ping(address, timeout)
        if result.ok:
            live.append((address, result.latency_ms))

    await asyncio.gather(*(probe(address) for address in addresses))
    live.sort(key=lambda item: ipaddress.ip_address(item[0]))
    log.info("Сканирование %s: живых %s из %s", cidr, len(live), len(addresses))
    return live, len(addresses)
