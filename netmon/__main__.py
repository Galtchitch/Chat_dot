"""Точка входа: ``python -m netmon`` — бот, ``check`` — разовая проверка, ``scan`` — поиск узлов."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import load_config

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Консоль Windows по умолчанию не умеет выводить кириллицу.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


async def _run_check(config, targets: list[str], timeout: float | None) -> int:
    from .checks import check
    from .models import Host
    from .storage import Storage

    hosts: list[Host] = []
    if targets:
        storage = Storage(config.database)
        for target in targets:
            hosts.append(storage.find_host(target) or Host(name=target, address=target))
    else:
        storage = Storage(config.database)
        hosts = storage.list_hosts()

    if not hosts:
        print("Нет узлов для проверки. Добавьте их в config.yaml или передайте адрес аргументом.")
        return 1

    effective_timeout = timeout or config.monitor.timeout
    results = await asyncio.gather(*(check(host, effective_timeout) for host in hosts))

    failed = 0
    for host, result in zip(hosts, results):
        if result.ok:
            latency = f"{result.latency_ms:.0f} мс" if result.latency_ms is not None else "ок"
            print(f"  OK   {host.name:<20} {host.target:<24} {latency}")
        else:
            failed += 1
            print(f"  FAIL {host.name:<20} {host.target:<24} {result.detail}")
    print(f"\nПроверено: {len(hosts)}, недоступно: {failed}")
    return 1 if failed else 0


async def _run_scan(config, args) -> int:
    from .models import Host
    from .scan import live_hosts, resolve_targets
    from .storage import Storage

    targets, unknown = resolve_targets(config.networks, args.targets)
    if unknown:
        print("Не понял: " + ", ".join(unknown))
        return 2
    if not targets:
        print("Сети не заданы. Добавьте раздел networks в config.yaml или укажите CIDR.")
        return 2

    storage = Storage(config.database) if args.add else None
    timeout = args.timeout or config.scan.timeout
    added_total = 0

    for title, cidr, network in targets:
        live, total = await live_hosts(cidr, timeout, config.scan.workers, config.scan.max_hosts)
        print(f"\n{title} ({cidr}): живых {len(live)} из {total}")
        for address, latency in live:
            suffix = f"{latency:.0f} мс" if latency is not None else ""
            print(f"  {address:<16} {suffix}")
        if storage is not None:
            added = 0
            for address, _latency in live:
                if storage.find_host(address) is not None:
                    continue
                storage.add_host(Host(name=address, address=address, network=network))
                added += 1
            added_total += added
            print(f"  добавлено в мониторинг: {added}")

    if storage is not None:
        print(f"\nВсего добавлено: {added_total}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netmon",
        description="Telegram-бот мониторинга доступности узлов локальной сети.",
    )
    parser.add_argument("-c", "--config", help="путь к файлу конфигурации (по умолчанию config.yaml)")
    parser.add_argument("--log-level", default="INFO", help="уровень логирования (DEBUG, INFO, WARNING, ERROR)")
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser("check", help="проверить узлы один раз и выйти (без Telegram)")
    check_parser.add_argument("targets", nargs="*", help="имена узлов или адреса; без них — все узлы из базы")
    check_parser.add_argument("-t", "--timeout", type=float, default=None, help="таймаут проверки, сек")

    scan_parser = subparsers.add_parser("scan", help="просканировать подсети и показать живые узлы")
    scan_parser.add_argument("targets", nargs="*", help="имена сетей из config.yaml или CIDR; без них — все сети")
    scan_parser.add_argument("--add", action="store_true", help="добавить найденные узлы в мониторинг")
    scan_parser.add_argument("-t", "--timeout", type=float, default=None, help="таймаут отклика, сек")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"Ошибка в конфигурации: {exc}", file=sys.stderr)
        return 2

    if args.command == "check":
        return asyncio.run(_run_check(config, args.targets, args.timeout))
    if args.command == "scan":
        return asyncio.run(_run_scan(config, args))

    if not config.telegram.token:
        print(
            "Не задан токен Telegram-бота.\n"
            "Укажите его в файле .env (TELEGRAM_BOT_TOKEN=...) или в config.yaml (telegram.token).",
            file=sys.stderr,
        )
        return 2

    from .bot import run

    run(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
