"""Сканирование подсетей: поиск живых узлов."""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from .checks import ping
from .config import NetworkConfig
from .names import resolve_many
from .storage import Storage

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


def pick_name(storage: Storage, resolved: str, address: str) -> str:
    """Имя для узла: найденное, если оно свободно, иначе сам адрес."""
    candidate = (resolved or "").strip() or address
    if candidate == address:
        return address
    existing = storage.find_host(candidate)
    if existing is None or existing.address == address:
        return candidate
    return address


async def live_hosts(
    cidr: str,
    timeout: float = 1.0,
    workers: int = 256,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    names: bool = True,
    name_timeout: float = 2.0,
    name_workers: int = 16,
) -> tuple[list[tuple[str, float | None, str]], int]:
    """Пропинговать подсеть.

    Возвращает список ``(адрес, задержка_мс, имя)`` и число проверенных адресов.
    Имя определяется только у живых узлов: обратный DNS, затем NetBIOS.
    """
    addresses = _addresses(cidr, max_hosts)
    semaphore = asyncio.Semaphore(max(1, workers))
    found: list[tuple[str, float | None]] = []

    async def probe(address: str) -> None:
        async with semaphore:
            result = await ping(address, timeout)
        if result.ok:
            found.append((address, result.latency_ms))

    await asyncio.gather(*(probe(address) for address in addresses))

    resolved: dict[str, str] = {}
    if names and found:
        resolved = await resolve_many([address for address, _ in found], name_workers, name_timeout)

    live = sorted(
        ((address, latency, resolved.get(address, "")) for address, latency in found),
        key=lambda item: ipaddress.ip_address(item[0]),
    )
    log.info("Сканирование %s: живых %s из %s", cidr, len(live), len(addresses))
    return live, len(addresses)
