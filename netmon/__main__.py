"""Точка входа: ``python -m netmon`` — бот, ``check`` — разовая проверка, ``scan`` — поиск узлов, ``certs`` — набор ЦС."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import load_config

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
LOG_MAX_BYTES = 1_000_000
LOG_BACKUPS = 3


def setup_logging(level: str, log_path: str | Path | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_path:
        path = Path(log_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(
                RotatingFileHandler(
                    path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"
                )
            )
        except OSError:
            pass  # без файла журнала работаем дальше, только в консоль

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )
    # httpx пишет строку на каждый запрос при опросе Telegram — это шум.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # Консоль Windows по умолчанию не умеет выводить кириллицу.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _log_file(config) -> Path | None:
    """Журнал кладём рядом с базой: data/netmon.log."""
    database = (config.database or "").strip()
    if not database or database == ":memory:":
        return None
    return Path(database).expanduser().parent / "netmon.log"


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
    from .scan import live_hosts, pick_name, resolve_targets
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
    with_names = config.scan.resolve_names and not args.no_names
    added_total = 0
    renamed_total = 0

    for title, cidr, network in targets:
        live, total = await live_hosts(
            cidr,
            timeout,
            config.scan.workers,
            config.scan.max_hosts,
            names=with_names,
            name_timeout=config.scan.name_timeout,
        )
        print(f"\n{title} ({cidr}): живых {len(live)} из {total}")
        for address, latency, name in live:
            latency_text = f"{latency:.0f} мс" if latency is not None else ""
            print(f"  {address:<16} {name:<20} {latency_text}")

        if storage is not None:
            added = 0
            renamed = 0
            for address, _latency, name in live:
                existing = storage.find_host(address)
                if existing is not None:
                    if name and existing.name == existing.address:
                        candidate = pick_name(storage, name, address)
                        if candidate != existing.name and storage.rename_host(existing.name, candidate):
                            renamed += 1
                    continue
                host_name = pick_name(storage, name, address)
                storage.add_host(Host(name=host_name, address=address, network=network))
                added += 1
            added_total += added
            renamed_total += renamed
            line = f"  добавлено в мониторинг: {added}"
            if renamed:
                line += f", уточнено имён: {renamed}"
            print(line)

    if storage is not None:
        summary = f"\nВсего добавлено: {added_total}"
        if renamed_total:
            summary += f", уточнено имён: {renamed_total}"
        print(summary)
    return 0


def _run_certs(config, args) -> int:
    from .certs import DEFAULT_BUNDLE, build_bundle

    target = args.output or config.telegram.ca_bundle or str(DEFAULT_BUNDLE)
    if target.lower() == "auto":
        target = str(DEFAULT_BUNDLE)

    path, added = build_bundle(target)
    print(f"Набор сертификатов: {path} ({path.stat().st_size} байт, системных корней: {added})")

    if not config.telegram.ca_bundle:
        shown = str(path).replace("\\", "/")
        print(
            "Чтобы бот его использовал, добавьте в config.yaml:\n"
            "  telegram:\n"
            f"    ca_bundle: {shown}"
        )
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
    scan_parser.add_argument("--no-names", action="store_true", help="не определять имена узлов (быстрее)")
    scan_parser.add_argument("-t", "--timeout", type=float, default=None, help="таймаут отклика, сек")

    certs_parser = subparsers.add_parser(
        "certs", help="собрать набор доверенных ЦС из системного хранилища"
    )
    certs_parser.add_argument(
        "-o", "--output", default=None, help="куда записать (по умолчанию certs/ca-bundle.pem)"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except ValueError as exc:
        setup_logging(args.log_level)
        print(f"Ошибка в конфигурации: {exc}", file=sys.stderr)
        return 2

    log_path = _log_file(config)
    setup_logging(args.log_level, log_path)
    logger = logging.getLogger("netmon")
    if log_path:
        logger.info("Журнал: %s", log_path)
    logger.info("Конфигурация: %s", config.source or "config.yaml")
    logger.info(
        "Проверка: каждые %s с, тревога после %s неудач, повтор о недоступных: %s",
        config.monitor.default_interval,
        config.monitor.flap_threshold,
        f"{config.monitor.down_repeat_minutes} мин"
        if config.monitor.down_repeat_minutes
        else "не напоминать",
    )

    if args.command == "check":
        return asyncio.run(_run_check(config, args.targets, args.timeout))
    if args.command == "scan":
        return asyncio.run(_run_scan(config, args))
    if args.command == "certs":
        return _run_certs(config, args)

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
