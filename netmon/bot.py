"""Telegram-бот: команды и рассылка оповещений."""

from __future__ import annotations

import asyncio
import html
import ipaddress
import logging
from pathlib import Path
import time

from telegram import BotCommand, Update
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    Defaults,
)

from .checks import check as run_check
from .config import Config, NetworkConfig
from .models import KINDS, Host
from .monitor import Monitor
from .notify import Notifier, format_event
from .scan import live_hosts, pick_name, resolve_targets
from .schedule import Clock
from .storage import Storage

log = logging.getLogger("netmon.bot")

STATUS_EMOJI = {True: "🟢", False: "🔴", None: "⚪"}

COMMANDS = [
    BotCommand("status", "Состояние узлов по сетям"),
    BotCommand("down", "Только недоступные узлы"),
    BotCommand("check", "Проверить сейчас: /check [имя|адрес]"),
    BotCommand("scan", "Найти узлы в подсети: /scan [сеть|CIDR]"),
    BotCommand("scan_add", "Найти и добавить узлы: /scan_add [сеть|CIDR]"),
    BotCommand("add", "Добавить узел: /add имя адрес [icmp|tcp|http] [порт] [интервал]"),
    BotCommand("remove", "Удалить узел: /remove имя"),
    BotCommand("enable", "Включить проверки: /enable имя"),
    BotCommand("disable", "Отключить проверки: /disable имя"),
    BotCommand("mute", "Отключить оповещения"),
    BotCommand("unmute", "Включить оповещения"),
    BotCommand("id", "Показать ID чата и пользователя"),
    BotCommand("help", "Справка"),
]

HELP_TEXT = (
    "<b>netmon</b> — мониторинг узлов локальной сети.\n\n"
    "Команды:\n"
    "/status — состояние узлов, сгруппировано по сетям\n"
    "/down — только недоступные узлы\n"
    "/check [имя|адрес] — проверить сейчас (без аргумента — все узлы)\n"
    "/scan [сеть|CIDR] — найти живые узлы в подсети\n"
    "/scan_add [сеть|CIDR] — найти и добавить их в мониторинг\n"
    "/add имя адрес [icmp|tcp|http] [порт] [интервал] — добавить узел\n"
    "/remove имя — удалить узел\n"
    "/disable имя, /enable имя — пауза и возобновление проверок\n"
    "/mute, /unmute — отключить и включить оповещения\n"
    "/id — ID чата и пользователя\n\n"
    "Примеры:\n"
    "<code>/add router 192.168.124.1</code>\n"
    "<code>/add nas 192.168.147.10 tcp 445</code>\n"
    "<code>/scan Склад</code>\n"
)

# --------------------------------------------------------------------- утилиты


def _is_admin(config: Config, update: Update) -> bool:
    """Проверка прав. Если admin_ids пуст — разрешено всем (удобно в LAN)."""
    admins = config.telegram.admin_ids
    if not admins:
        return True
    user = update.effective_user
    return bool(user and user.id in admins)


def _human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds} с"
    minutes, _ = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} мин"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} ч {minutes} мин"
    days, hours = divmod(hours, 24)
    return f"{days} д {hours} ч"


def _fmt_host(host: Host) -> str:
    title = f"<b>{html.escape(host.name)}</b>"
    # Если узел назван по адресу, не дублируем одно и то же.
    if host.target.strip() != host.name.strip():
        title += f" (<code>{html.escape(host.target)}</code>)"
    line = f"{STATUS_EMOJI[host.ok]} {title}"
    extras: list[str] = []
    if host.ok is None:
        extras.append("ещё не проверялся")
    elif host.ok:
        if host.latency is not None:
            extras.append(f"{host.latency:.0f} мс")
    else:
        if host.changed_at:
            extras.append(f"недоступен {_human_duration(time.time() - host.changed_at)}")
        if host.detail:
            extras.append(html.escape(host.detail[:120]))
    if not host.enabled:
        extras.append("проверки отключены")
    if extras:
        line += " — " + ", ".join(extras)
    return line


def _live_line(address: str, latency: float | None, name: str) -> str:
    """Строка результата сканирования: адрес, имя и задержка."""
    line = f"  <code>{html.escape(address)}</code>"
    if name:
        line += f" <b>{html.escape(name)}</b>"
    if latency is not None:
        line += f" — {latency:.0f} мс"
    return line


def _status_sort_key(host: Host) -> tuple[int, str]:
    rank = {False: 0, None: 1, True: 2}
    return rank[host.ok], host.name.lower()


def _group_by_network(
    hosts: list[Host], networks: list[NetworkConfig]
) -> list[tuple[str, list[Host]]]:
    """Сгруппировать узлы по сетям в порядке из конфигурации."""
    groups: dict[str, list[Host]] = {}
    for host in hosts:
        groups.setdefault(host.network or "", []).append(host)

    ordered: list[tuple[str, list[Host]]] = []
    for network in networks:
        items = groups.pop(network.name, None)
        if items:
            ordered.append((network.name, items))
    for name in sorted(name for name in groups if name):
        ordered.append((name, groups[name]))
    if "" in groups:
        ordered.append(("Без сети", groups[""]))
    return ordered


# ---------------------------------------------------------------- обработчики


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    storage: Storage = context.application.bot_data["storage"]
    clock: Clock = context.application.bot_data["clock"]
    chat = update.effective_chat
    title = chat.title or getattr(chat, "full_name", "") or ""
    created = storage.add_subscriber(chat.id, title)
    prefix = "Вы подписаны на оповещения." if created else "Вы уже подписаны."
    await update.message.reply_text(
        f"{prefix}\nУведомления: {clock.describe()}.\n\n{HELP_TEXT}"
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_TEXT)


async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    await update.message.reply_text(
        f"Чат: <code>{update.effective_chat.id}</code>\n"
        f"Пользователь: <code>{user.id if user else '—'}</code>"
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    clock: Clock = context.application.bot_data["clock"]

    hosts = storage.list_hosts()
    if not hosts:
        await update.message.reply_text(
            "Список узлов пуст. Добавьте узел: /add имя адрес,\n"
            "или найдите узлы в подсети: /scan_add " + (config.networks[0].cidr if config.networks else "192.168.1.0/24")
        )
        return

    down = sum(1 for host in hosts if host.ok is False)
    known = [host for host in hosts if host.ok is not None]
    blocks = [
        f"Узлов: {len(hosts)}, доступно {len(known) - down} из {len(known)}, проблемных {down}"
        f"\nУведомления: {clock.describe()}"
    ]
    for title, items in _group_by_network(sorted(hosts, key=_status_sort_key), config.networks):
        lines = "\n".join(_fmt_host(host) for host in items)
        blocks.append(f"<b>Сеть: {html.escape(title)}</b> ({len(items)})\n{lines}")
    await update.message.reply_text("\n\n".join(blocks))


async def cmd_down(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    storage: Storage = context.application.bot_data["storage"]
    hosts = [host for host in storage.list_hosts() if host.ok is False]
    if not hosts:
        await update.message.reply_text("🔴 Недоступных узлов нет.")
        return
    await update.message.reply_text("\n".join(_fmt_host(host) for host in hosts))


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    monitor: Monitor = context.application.bot_data["monitor"]

    if context.args:
        target = context.args[0]
        host = storage.find_host(target)
        if host is None:
            result = await run_check(Host(name=target, address=target), config.monitor.timeout)
            suffix = " (icmp, без сохранения)"
        else:
            result = await monitor.probe_now(host)
            suffix = ""
        emoji = "🟢" if result.ok else "🔴"
        detail = f"{result.latency_ms:.0f} мс" if result.latency_ms is not None else result.detail
        await update.message.reply_text(
            f"{emoji} <b>{html.escape(target)}</b>{suffix} — {html.escape(str(detail))}"
        )
        return

    hosts = storage.list_hosts(enabled_only=True)
    if not hosts:
        await update.message.reply_text("Проверять нечего: список узлов пуст.")
        return
    results = await asyncio.gather(*(monitor.probe_now(host) for host in hosts))
    lines = []
    for host, result in zip(hosts, results):
        emoji = "🟢" if result.ok else "🔴"
        detail = f"{result.latency_ms:.0f} мс" if result.latency_ms is not None else result.detail
        lines.append(f"{emoji} <b>{html.escape(host.name)}</b> — {html.escape(str(detail))}")
    await update.message.reply_text(f"Проверено узлов: {len(hosts)}\n\n" + "\n".join(lines))


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    if not _is_admin(config, update):
        await update.message.reply_text("Недостаточно прав для изменения списка узлов.")
        return

    args = context.args or []
    if len(args) < 2:
        await update.message.reply_text(
            "Использование: <code>/add имя адрес [icmp|tcp|http] [порт] [интервал]</code>\n"
            "Пример: <code>/add nas 192.168.147.10 tcp 445</code>"
        )
        return

    name, address = args[0], args[1]
    kind = args[2].lower() if len(args) > 2 else "icmp"
    if kind not in KINDS:
        await update.message.reply_text(f"Тип проверки должен быть одним из: {', '.join(KINDS)}")
        return

    try:
        port = int(args[3]) if len(args) > 3 else None
        interval = int(args[4]) if len(args) > 4 else None
    except ValueError:
        await update.message.reply_text("Порт и интервал должны быть целыми числами.")
        return

    if kind == "tcp" and not port:
        await update.message.reply_text("Для типа tcp обязательно укажите порт.")
        return
    if interval is not None and interval < 5:
        await update.message.reply_text("Минимальный интервал проверки — 5 секунд.")
        return

    network = _network_for(address, config.networks)
    storage.add_host(Host(name=name, address=address, kind=kind, port=port, interval=interval, network=network))
    suffix = f", сеть: {network}" if network else ""
    await update.message.reply_text(
        f"Узел добавлен: <b>{html.escape(name)}</b> (<code>{html.escape(address)}</code>), "
        f"проверка: {kind}{html.escape(suffix)}"
    )


def _network_for(address: str, networks: list[NetworkConfig]) -> str:
    """Определить сеть по адресу узла."""
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return ""
    for network in networks:
        candidate = ipaddress.ip_network(network.cidr, strict=False)
        if ip in candidate:
            return network.name
    return ""


async def cmd_remove(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    if not _is_admin(config, update):
        await update.message.reply_text("Недостаточно прав.")
        return
    if not context.args:
        await update.message.reply_text("Использование: <code>/remove имя</code>")
        return
    name = context.args[0]
    if storage.remove_host(name):
        await update.message.reply_text(f"Узел <b>{html.escape(name)}</b> удалён.")
    else:
        await update.message.reply_text(f"Узел <b>{html.escape(name)}</b> не найден.")


async def _toggle(update: Update, context: ContextTypes.DEFAULT_TYPE, enabled: bool) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    if not _is_admin(config, update):
        await update.message.reply_text("Недостаточно прав.")
        return
    if not context.args:
        await update.message.reply_text("Укажите имя узла.")
        return
    name = context.args[0]
    if storage.set_enabled(name, enabled):
        state = "включены" if enabled else "отключены"
        await update.message.reply_text(f"Проверки узла <b>{html.escape(name)}</b> {state}.")
    else:
        await update.message.reply_text(f"Узел <b>{html.escape(name)}</b> не найден.")


async def cmd_enable(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle(update, context, True)


async def cmd_disable(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle(update, context, False)


async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    storage: Storage = context.application.bot_data["storage"]
    storage.set_notify(update.effective_chat.id, False)
    await update.message.reply_text("Оповещения отключены. Вернуть: /unmute")


async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    storage: Storage = context.application.bot_data["storage"]
    storage.add_subscriber(update.effective_chat.id, update.effective_chat.title or "")
    storage.set_notify(update.effective_chat.id, True)
    await update.message.reply_text("Оповещения включены.")


async def _resolve(
    update: Update, config: Config, args: list[str]
) -> list[tuple[str, str, str]] | None:
    if not config.networks and not args:
        await update.message.reply_text(
            "В config.yaml не заданы сети (раздел networks) и не указан CIDR.\n"
            "Пример: <code>/scan 192.168.124.0/24</code>"
        )
        return None
    targets, unknown = resolve_targets(config.networks, args)
    if unknown:
        await update.message.reply_text(
            "Не понял: " + ", ".join(html.escape(item) for item in unknown) +
            "\nУкажите имя сети из config.yaml или CIDR, например 192.168.124.0/24"
        )
        return None
    if not targets:
        await update.message.reply_text("Нет сетей для сканирования.")
        return None
    return targets


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    targets = await _resolve(update, config, context.args or [])
    if targets is None:
        return

    await update.message.reply_text(
        "🔍 Сканирую: " + ", ".join(f"{html.escape(title)} ({cidr})" for title, cidr, _ in targets)
    )
    blocks = []
    for title, cidr, _network in targets:
        live, total = await live_hosts(
            cidr,
            config.scan.timeout,
            config.scan.workers,
            config.scan.max_hosts,
            names=config.scan.resolve_names,
            name_timeout=config.scan.name_timeout,
        )
        if live:
            shown = "\n".join(_live_line(*item) for item in live[:60])
            if len(live) > 60:
                shown += f"\n  … и ещё {len(live) - 60}"
        else:
            shown = "  живых узлов не найдено"
        blocks.append(
            f"<b>{html.escape(title)}</b> ({cidr}): живых {len(live)} из {total}\n{shown}"
        )
    await update.message.reply_text("\n\n".join(blocks))


async def cmd_scan_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.application.bot_data["config"]
    storage: Storage = context.application.bot_data["storage"]
    if not _is_admin(config, update):
        await update.message.reply_text("Недостаточно прав.")
        return

    targets = await _resolve(update, config, context.args or [])
    if targets is None:
        return

    await update.message.reply_text(
        "🔍 Сканирую и добавляю: " + ", ".join(cidr for _title, cidr, _n in targets)
    )
    added_total = 0
    renamed_total = 0
    blocks = []
    for title, cidr, network in targets:
        live, total = await live_hosts(
            cidr,
            config.scan.timeout,
            config.scan.workers,
            config.scan.max_hosts,
            names=config.scan.resolve_names,
            name_timeout=config.scan.name_timeout,
        )
        added_names: list[str] = []
        renamed = 0
        for address, _latency, name in live:
            existing = storage.find_host(address)
            if existing is not None:
                # Узел уже под мониторингом: уточним имя, если он назван по адресу.
                if name and existing.name == existing.address:
                    candidate = pick_name(storage, name, address)
                    if candidate != existing.name and storage.rename_host(existing.name, candidate):
                        renamed += 1
                continue
            host_name = pick_name(storage, name, address)
            storage.add_host(Host(name=host_name, address=address, network=network))
            added_names.append(host_name)
            added_total += 1
        renamed_total += renamed
        shown = ""
        if added_names:
            shown = "\n  " + ", ".join(html.escape(item) for item in added_names[:25])
            if len(added_names) > 25:
                shown += f" … и ещё {len(added_names) - 25}"
        blocks.append(
            f"<b>{html.escape(title)}</b> ({cidr}): найдено {len(live)} из {total}, "
            f"добавлено {len(added_names)}, уточнено имён {renamed}{shown}"
        )

    summary = f"\n\nВсего добавлено: {added_total}"
    if renamed_total:
        summary += f", уточнено имён: {renamed_total}"
    await update.message.reply_text("\n".join(blocks) + summary)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("Ошибка при обработке обновления", exc_info=context.error)


# ------------------------------------------------------------------ сборка


async def _post_init(app: Application) -> None:
    config: Config = app.bot_data["config"]
    storage: Storage = app.bot_data["storage"]
    clock = Clock(config.notify.window, config.notify.timezone)

    notifier = Notifier(app, storage, clock)
    monitor = Monitor(storage, config, on_event=notifier, on_tick=notifier.tick)
    app.bot_data["clock"] = clock
    app.bot_data["notifier"] = notifier
    app.bot_data["monitor"] = monitor
    app.bot_data["monitor_task"] = asyncio.create_task(monitor.run(), name="netmon-monitor")

    log.info("Окно уведомлений: %s", clock.describe())
    try:
        await app.bot.set_my_commands(COMMANDS)
    except TelegramError as exc:
        log.warning("Не удалось установить список команд: %s", exc)


async def _post_shutdown(app: Application) -> None:
    monitor: Monitor | None = app.bot_data.get("monitor")
    task: asyncio.Task | None = app.bot_data.get("monitor_task")
    if monitor:
        monitor.stop()
    if task:
        try:
            await asyncio.wait_for(task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()


def _resolve_ca_bundle(setting: str) -> str:
    """Путь к PEM-набору доверенных ЦС или пустая строка."""
    if not setting:
        return ""
    if setting.lower() == "auto":
        from .certs import DEFAULT_BUNDLE, build_bundle

        path, added = build_bundle(DEFAULT_BUNDLE)
        log.info("Собран набор сертификатов: %s (системных корней: %s)", path, added)
        return str(path)
    return str(Path(setting).expanduser())


def create_app(config: Config, storage: Storage) -> Application:
    from telegram.request import HTTPXRequest

    defaults = Defaults(parse_mode=ParseMode.HTML)
    builder = Application.builder().token(config.telegram.token).defaults(defaults)

    ca_bundle = _resolve_ca_bundle(config.telegram.ca_bundle)
    if ca_bundle:
        if Path(ca_bundle).is_file():
            # Доверяем корпоративному прокси: httpx получает свой набор ЦС.
            builder = builder.request(
                HTTPXRequest(httpx_kwargs={"verify": ca_bundle})
            ).get_updates_request(HTTPXRequest(httpx_kwargs={"verify": ca_bundle}))
            log.info("Дополнительный набор сертификатов: %s", ca_bundle)
        else:
            log.warning("Файл ca_bundle не найден: %s — продолжаю с системным набором", ca_bundle)

    if config.telegram.api_base:
        root = config.telegram.api_base.rstrip("/")
        if root.endswith("/bot"):
            root = root[: -len("/bot")]
        builder = builder.base_url(f"{root}/bot").base_file_url(f"{root}/file/bot")
        log.info("Используется локальный Telegram Bot API: %s", root)

    app = builder.post_init(_post_init).post_shutdown(_post_shutdown).build()
    app.bot_data["config"] = config
    app.bot_data["storage"] = storage

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler(["status", "list", "hosts"], cmd_status))
    app.add_handler(CommandHandler("down", cmd_down))
    app.add_handler(CommandHandler(["check", "test"], cmd_check))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler(["scan_add", "scanadd"], cmd_scan_add))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler(["remove", "del"], cmd_remove))
    app.add_handler(CommandHandler("enable", cmd_enable))
    app.add_handler(CommandHandler(["disable", "pause"], cmd_disable))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_error_handler(on_error)
    return app


def run(config: Config) -> None:
    storage = Storage(config.database)
    added = storage.seed(config.seed_hosts)
    if added:
        log.info("Из конфигурации добавлено узлов: %s", added)
    app = create_app(config, storage)
    log.info("Бот запущен, ожидаю команды")
    app.run_polling(allowed_updates=Update.ALL_TYPES, close_loop=False)
