"""Тесты: состояние мониторинга, хранилище, окно уведомлений, сканирование."""

from __future__ import annotations

import os
import shutil
import ssl
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

from netmon.checks import CheckResult
from netmon.config import Config, MonitorConfig, NetworkConfig
from netmon.models import Host
from netmon.monitor import Event, Monitor
from netmon.names import parse_nbtstat, resolve, short_name
from netmon.schedule import Clock, parse_window
from netmon.scan import live_hosts, pick_name, resolve_targets
from netmon.storage import Storage

FAIL = CheckResult(False, None, "нет ответа")
OK = CheckResult(True, 1.5, "ответ получен")


def at(hours: int, minutes: int = 0) -> float:
    """Локальная метка времени на конкретный час — для детерминированных тестов."""
    return datetime(2026, 1, 15, hours, minutes).timestamp()


def make_storage(test: unittest.TestCase) -> Storage:
    test.tmp = tempfile.TemporaryDirectory()
    test.addCleanup(test.tmp.cleanup)
    storage = Storage(os.path.join(test.tmp.name, "test.sqlite3"))
    test.addCleanup(storage.close)
    return storage


# ----------------------------------------------------------------- расписание


class ClockTest(unittest.TestCase):
    def test_parse_window(self) -> None:
        self.assertEqual(parse_window("07:00-22:30"), (420, 1350))
        self.assertEqual(parse_window("7-22"), (420, 1320))
        self.assertIsNone(parse_window(""))
        self.assertIsNone(parse_window("always"))
        with self.assertRaises(ValueError):
            parse_window("22:30")
        with self.assertRaises(ValueError):
            parse_window("25:00-26:00")

    def test_window_07_00_22_30(self) -> None:
        clock = Clock("07:00-22:30")
        self.assertTrue(clock.is_open(at(7, 0)))
        self.assertTrue(clock.is_open(at(12, 0)))
        self.assertTrue(clock.is_open(at(22, 29)))
        self.assertFalse(clock.is_open(at(22, 30)))
        self.assertFalse(clock.is_open(at(23, 0)))
        self.assertFalse(clock.is_open(at(6, 59)))
        self.assertEqual(clock.describe(), "07:00–22:30")

    def test_window_across_midnight(self) -> None:
        clock = Clock("22:30-07:00")
        self.assertTrue(clock.is_open(at(23, 0)))
        self.assertTrue(clock.is_open(at(3, 0)))
        self.assertFalse(clock.is_open(at(12, 0)))

    def test_window_always(self) -> None:
        clock = Clock("")
        self.assertTrue(clock.is_open(at(3, 0)))
        self.assertEqual(clock.describe(), "круглосуточно")

    def test_timezone(self) -> None:
        try:
            clock = Clock("07:00-22:30", "Europe/Moscow")
        except ValueError:
            self.skipTest("нет базы часовых поясов (tzdata)")
        # 04:00 UTC = 07:00 MSK — окно открыто; 03:00 UTC = 06:00 MSK — закрыто.
        self.assertTrue(clock.is_open(datetime(2026, 1, 15, 4, 0, tzinfo=timezone.utc).timestamp()))
        self.assertFalse(clock.is_open(datetime(2026, 1, 15, 3, 0, tzinfo=timezone.utc).timestamp()))


# ------------------------------------------------------------------ мониторинг


class MonitorTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.storage = make_storage(self)
        self.config = Config(
            monitor=MonitorConfig(
                default_interval=1,
                timeout=1,
                workers=4,
                flap_threshold=2,
                down_repeat_minutes=0,
            )
        )
        self.events: list[tuple[str, str]] = []

        async def on_event(event):
            self.events.append((event.kind, event.host.name))

        self.monitor = Monitor(self.storage, self.config, on_event=on_event)

    def _add(self, name: str = "node", address: str = "10.0.0.1") -> None:
        self.storage.add_host(Host(name=name, address=address))

    async def _apply(self, *results: CheckResult) -> None:
        async def fake_check(host, timeout):
            return results[self._step]

        for step, result in enumerate(results):
            self._step = step
            host = self.storage.get_host("node")
            with mock.patch("netmon.monitor.check", new=fake_check):
                pair = await self.monitor._probe(host)
            await self.monitor._apply([pair])

    async def test_down_only_after_threshold(self) -> None:
        self._add()
        await self._apply(FAIL)
        self.assertEqual(self.events, [], "одной неудачи мало для оповещения")
        self.assertIsNone(self.storage.get_host("node").ok)

        await self._apply(FAIL)
        self.assertEqual(self.events, [("down", "node")])
        self.assertFalse(self.storage.get_host("node").ok)

    async def test_no_duplicate_down_events(self) -> None:
        self._add()
        await self._apply(FAIL, FAIL, FAIL, FAIL)
        self.assertEqual(self.events, [("down", "node")])

    async def test_recovery_emits_up(self) -> None:
        self._add()
        await self._apply(FAIL, FAIL)
        await self._apply(OK)
        self.assertEqual([kind for kind, _ in self.events], ["down", "up"])
        host = self.storage.get_host("node")
        self.assertTrue(host.ok)
        self.assertEqual(host.consecutive_failures, 0)
        self.assertEqual(host.latency, 1.5)

    async def test_reminder_for_still_down(self) -> None:
        self.config.monitor.down_repeat_minutes = 1
        self._add()
        await self._apply(FAIL, FAIL)
        self.assertEqual([kind for kind, _ in self.events], ["down"])

        host = self.storage.get_host("node")
        self.storage.update_state(
            "node",
            ok=False,
            consecutive_failures=host.consecutive_failures,
            latency=None,
            detail=host.detail,
            changed_at=host.changed_at,
            last_notified=time.time() - 120,
        )
        await self._apply(FAIL)
        self.assertEqual([kind for kind, _ in self.events], ["down", "still_down"])


# ------------------------------------------------------------ окно и сводка


class _FakeBot:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []

    async def send_message(self, chat_id, text, **_kwargs):
        self.sent.append((chat_id, text))


class _FakeApp:
    def __init__(self) -> None:
        self.bot = _FakeBot()


class NotifierTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        from netmon.notify import Notifier

        self.storage = make_storage(self)
        self.storage.add_subscriber(1, "chat")
        self.app = _FakeApp()
        self.clock = Clock("07:00-22:30")
        self.notifier = Notifier(self.app, self.storage, self.clock)

    @staticmethod
    def _event(kind: str, moment: float) -> Event:
        host = Host(name="router", address="192.168.124.1", ok=kind != "up", changed_at=moment)
        return Event(host=host, kind=kind, result=FAIL, at=moment)

    async def test_event_outside_window_is_deferred(self) -> None:
        await self.notifier(self._event("down", at(23, 0)))
        self.assertEqual(self.app.bot.sent, [], "ночью оповещения не отправляются")
        self.assertEqual(len(self.storage.list_outbox()), 1)

    async def test_digest_sent_when_window_opens(self) -> None:
        await self.notifier(self._event("down", at(23, 0)))
        await self.notifier(self._event("up", at(23, 30)))
        self.assertEqual(len(self.storage.list_outbox()), 2)

        await self.notifier.tick(at(8, 0))
        self.assertEqual(len(self.app.bot.sent), 1)
        _chat_id, text = self.app.bot.sent[0]
        self.assertIn("Сводка", text)
        self.assertIn("router", text)
        self.assertEqual(self.storage.list_outbox(), [], "сводка очищает очередь")

    async def test_reminders_not_queued(self) -> None:
        await self.notifier(self._event("still_down", at(23, 0)))
        self.assertEqual(self.storage.list_outbox(), [])

    async def test_event_inside_window_sent_immediately(self) -> None:
        await self.notifier(self._event("down", at(12, 0)))
        self.assertEqual(len(self.app.bot.sent), 1)
        self.assertIn("недоступен", self.app.bot.sent[0][1])
        self.assertEqual(self.storage.list_outbox(), [])


# ---------------------------------------------------------------- хранилище


class StorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.storage = make_storage(self)

    def test_seed_is_idempotent(self) -> None:
        hosts = [{"name": "router", "address": "192.168.124.1", "network": "Сеть 124"}]
        self.assertEqual(self.storage.seed(hosts), 1)
        self.assertEqual(self.storage.seed(hosts), 0)
        self.assertEqual(self.storage.get_host("router").network, "Сеть 124")

    def test_add_find_remove(self) -> None:
        self.storage.add_host(
            Host(name="nas", address="192.168.147.10", kind="tcp", port=445, network="Сеть 147")
        )
        self.assertIsNotNone(self.storage.find_host("nas"))
        self.assertIsNotNone(self.storage.find_host("192.168.147.10"))
        host = self.storage.get_host("nas")
        self.assertEqual(host.target, "192.168.147.10:445")
        self.assertEqual(host.network, "Сеть 147")
        self.assertTrue(self.storage.set_enabled("nas", False))
        self.assertEqual(self.storage.list_hosts(enabled_only=True), [])
        self.assertTrue(self.storage.remove_host("nas"))
        self.assertFalse(self.storage.remove_host("nas"))

    def test_subscribers(self) -> None:
        self.assertTrue(self.storage.add_subscriber(1, "chat"))
        self.assertFalse(self.storage.add_subscriber(1, "chat"))
        self.storage.set_notify(1, False)
        self.assertEqual(self.storage.list_subscribers(notify_only=True), [])
        self.storage.set_notify(1, True)
        self.assertEqual(self.storage.list_subscribers(notify_only=True), [(1, True)])

    def test_rename_host_keeps_state(self) -> None:
        self.storage.add_host(Host(name="192.168.124.1", address="192.168.124.1"))
        self.storage.add_host(Host(name="nas", address="192.168.147.10"))
        self.storage.update_state(
            "192.168.124.1",
            ok=False,
            consecutive_failures=2,
            latency=None,
            detail="нет ответа",
            changed_at=10.0,
            last_notified=None,
        )
        self.assertTrue(self.storage.rename_host("192.168.124.1", "gw-124"))
        renamed = self.storage.get_host("gw-124")
        self.assertEqual(renamed.address, "192.168.124.1")
        self.assertFalse(renamed.ok)
        self.assertEqual(renamed.consecutive_failures, 2)
        self.assertIsNone(self.storage.get_host("192.168.124.1"))
        self.assertFalse(self.storage.rename_host("gw-124", "nas"), "имя занято")
        self.assertFalse(self.storage.rename_host("нет-такого", "другое"))

    def test_outbox(self) -> None:
        self.storage.add_outbox(1.0, "a", "down", "таймаут")
        self.storage.add_outbox(2.0, "a", "up", "")
        items = self.storage.list_outbox()
        self.assertEqual([item[3] for item in items], ["down", "up"])
        self.storage.remove_outbox([items[0][0]])
        self.assertEqual([item[3] for item in self.storage.list_outbox()], ["up"])


# ---------------------------------------------------------------- сканирование


class ResolveTargetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.networks = [
            NetworkConfig("Сеть 124", "192.168.124.0/24"),
            NetworkConfig("Сеть 147", "192.168.147.0/24"),
        ]

    def test_all_networks_by_default(self) -> None:
        targets, unknown = resolve_targets(self.networks, [])
        self.assertEqual(unknown, [])
        self.assertEqual([cidr for _t, cidr, _n in targets],
                         ["192.168.124.0/24", "192.168.147.0/24"])

    def test_by_name_and_cidr(self) -> None:
        targets, unknown = resolve_targets(self.networks, ["Сеть 147"])
        self.assertEqual([t[1] for t in targets], ["192.168.147.0/24"])
        self.assertEqual(targets[0][2], "Сеть 147")

        targets, unknown = resolve_targets(self.networks, ["10.0.0.0/24"])
        self.assertEqual(unknown, [])
        self.assertEqual(targets[0], ("10.0.0.0/24", "10.0.0.0/24", ""))

    def test_unknown_argument(self) -> None:
        _targets, unknown = resolve_targets(self.networks, ["нет-такой"])
        self.assertEqual(unknown, ["нет-такой"])


@unittest.skipUnless(shutil.which("ping"), "нет утилиты ping")
class ScanTest(unittest.IsolatedAsyncioTestCase):
    async def test_live_hosts_localhost(self) -> None:
        live, total = await live_hosts("127.0.0.1/32", timeout=2.0, workers=2)
        self.assertEqual(total, 1)
        self.assertEqual([address for address, _latency, _name in live], ["127.0.0.1"])

    async def test_names_can_be_skipped(self) -> None:
        live, _total = await live_hosts("127.0.0.1/32", timeout=2.0, workers=2, names=False)
        self.assertEqual([name for _address, _latency, name in live], [""])


class PickNameTest(unittest.TestCase):
    """Имя узла: найденное, если свободно, иначе адрес."""

    def setUp(self) -> None:
        self.storage = make_storage(self)
        self.storage.add_host(Host(name="nas", address="192.168.147.10"))

    def test_uses_resolved_name(self) -> None:
        self.assertEqual(pick_name(self.storage, "gw-124", "192.168.124.1"), "gw-124")

    def test_falls_back_to_address(self) -> None:
        self.assertEqual(pick_name(self.storage, "", "192.168.124.1"), "192.168.124.1")
        self.assertEqual(pick_name(self.storage, "   ", "192.168.124.1"), "192.168.124.1")

    def test_avoids_collision_with_other_host(self) -> None:
        self.assertEqual(pick_name(self.storage, "nas", "192.168.124.1"), "192.168.124.1")

    def test_same_address_keeps_name(self) -> None:
        self.assertEqual(pick_name(self.storage, "nas", "192.168.147.10"), "nas")


# --------------------------------------------------------------------- имена


class NamesTest(unittest.IsolatedAsyncioTestCase):
    def test_short_name(self) -> None:
        self.assertEqual(short_name("server01.corp.local"), "server01")
        self.assertEqual(short_name("server01."), "server01")
        self.assertEqual(short_name("  NAS  "), "NAS")
        self.assertEqual(short_name(""), "")
        self.assertEqual(short_name("   "), "")

    def test_parse_nbtstat(self) -> None:
        output = (
            "\nИмя узла NetBIOS     Тип        Состояние\n"
            "----------------------------------------------\n"
            "SERVER01             <00>  UNIQUE      Registered\n"
            "SERVER01             <20>  UNIQUE      Registered\n"
            "WORKGROUP            <00>  GROUP       Registered\n"
        )
        self.assertEqual(parse_nbtstat(output), "SERVER01")
        # Служебные имена браузеров пропускаем.
        self.assertEqual(parse_nbtstat("__MSBROWSE__   <00>  UNIQUE  Registered"), "")
        self.assertEqual(parse_nbtstat(""), "")

    async def test_resolve_returns_string(self) -> None:
        name = await resolve("127.0.0.1", timeout=5.0)
        self.assertIsInstance(name, str)

    async def test_resolve_empty_address(self) -> None:
        self.assertEqual(await resolve("", timeout=1.0), "")


# ------------------------------------------------------------- вид в сообщениях


class HostFormatTest(unittest.TestCase):
    def test_ip_as_name_is_not_duplicated(self) -> None:
        from netmon.bot import _fmt_host

        line = _fmt_host(Host(name="192.168.124.1", address="192.168.124.1", ok=False))
        self.assertEqual(line.count("192.168.124.1"), 1)
        self.assertNotIn("<code>", line)

    def test_real_name_shown_with_address(self) -> None:
        from netmon.bot import _fmt_host

        line = _fmt_host(Host(name="gw-124", address="192.168.124.1", ok=True))
        self.assertIn("gw-124", line)
        self.assertIn("192.168.124.1", line)

    def test_port_shown_when_name_is_address(self) -> None:
        from netmon.bot import _fmt_host

        line = _fmt_host(
            Host(name="192.168.147.10", address="192.168.147.10", kind="tcp", port=445, ok=True)
        )
        self.assertIn("192.168.147.10:445", line)

    def test_scan_line_contains_name(self) -> None:
        from netmon.bot import _live_line

        self.assertEqual(_live_line("192.168.124.1", 3.4, "gw-124"), "  <code>192.168.124.1</code> <b>gw-124</b> — 3 мс")
        self.assertEqual(_live_line("192.168.124.1", None, ""), "  <code>192.168.124.1</code>")


# ------------------------------------------------- настройки и сертификаты


class ConfigTest(unittest.TestCase):
    def _write(self, text: str) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "config.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_reads_networks_and_ca_bundle(self) -> None:
        from netmon.config import load_config

        path = self._write(
            "telegram:\n"
            "  ca_bundle: certs/ca.pem\n"
            "notify:\n"
            "  window: \"07:00-22:30\"\n"
            "networks:\n"
            "  - name: Сеть 124\n"
            "    cidr: 192.168.124.0/24\n"
        )
        config = load_config(path)
        self.assertEqual(config.telegram.ca_bundle, "certs/ca.pem")
        self.assertEqual(config.notify.window, "07:00-22:30")
        self.assertEqual(config.networks[0].name, "Сеть 124")
        self.assertEqual(config.networks[0].cidr, "192.168.124.0/24")

    def test_bad_cidr_raises(self) -> None:
        from netmon.config import load_config

        path = self._write("networks:\n  - name: N\n    cidr: 300.0.0.0/24\n")
        with self.assertRaises(ValueError):
            load_config(path)

    def test_scan_name_options(self) -> None:
        from netmon.config import load_config

        config = load_config(self._write("scan:\n  resolve_names: false\n  name_timeout: 5\n"))
        self.assertFalse(config.scan.resolve_names)
        self.assertEqual(config.scan.name_timeout, 5.0)

        defaults = load_config(self._write("telegram:\n  token: \"\"\n"))
        self.assertTrue(defaults.scan.resolve_names)
        self.assertEqual(defaults.scan.name_timeout, 2.0)


class CertsTest(unittest.TestCase):
    def test_der_to_pem(self) -> None:
        from netmon.certs import der_to_pem

        pem = der_to_pem(b"\x30\x03\x02\x01\x01")
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertIn("-----END CERTIFICATE-----", pem)

    @unittest.skipUnless(hasattr(ssl, "enum_certificates"), "нет системного хранилища (не Windows)")
    def test_build_bundle_is_loadable(self) -> None:
        from netmon.certs import build_bundle

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path, added = build_bundle(os.path.join(tmp.name, "ca-bundle.pem"))
        self.assertGreater(added, 0)
        self.assertIn("BEGIN CERTIFICATE", path.read_text(encoding="ascii"))
        # OpenSSL должен принять файл целиком.
        ssl.create_default_context(cafile=str(path))


# ------------------------------------------------------------- сборка бота


class AppBuildTest(unittest.TestCase):
    def test_commands_and_handlers(self) -> None:
        from netmon.bot import COMMANDS, create_app

        for command in COMMANDS:
            self.assertRegex(command.command, r"^[a-z0-9_]{1,32}$", command.command)

        config = Config()
        config.telegram.token = "123456:TESTTOKEN"
        app = create_app(config, make_storage(self))
        self.assertEqual(len(app.handlers[0]), 14)

    def test_help_mentions_existing_commands(self) -> None:
        import re

        from netmon.bot import COMMANDS, HELP_TEXT

        known = {command.command for command in COMMANDS}
        mentioned = set(re.findall(r"(?<!<)/([a-z0-9_]+)", HELP_TEXT))
        unknown = mentioned - known
        self.assertEqual(unknown, set(), f"в справке упомянуты неизвестные команды: {unknown}")


# ------------------------------------------------------------- группировка


class GroupingTest(unittest.TestCase):
    def setUp(self) -> None:
        from netmon.bot import _group_by_network

        self.group = _group_by_network
        self.networks = [
            NetworkConfig("Сеть 124", "192.168.124.0/24"),
            NetworkConfig("Сеть 147", "192.168.147.0/24"),
        ]

    def test_grouping_order(self) -> None:
        hosts = [
            Host("b", "192.168.124.1", network="Сеть 124"),
            Host("a", "192.168.147.1", network="Сеть 147"),
            Host("c", "10.0.0.1"),
        ]
        groups = self.group(hosts, self.networks)
        self.assertEqual([title for title, _ in groups], ["Сеть 124", "Сеть 147", "Без сети"])
        self.assertEqual([host.name for host in groups[0][1]], ["b"])

    def test_detect_network_by_address(self) -> None:
        from netmon.bot import _network_for

        self.assertEqual(_network_for("192.168.124.55", self.networks), "Сеть 124")
        self.assertEqual(_network_for("192.168.147.1", self.networks), "Сеть 147")
        self.assertEqual(_network_for("10.0.0.1", self.networks), "")
        self.assertEqual(_network_for("не-адрес", self.networks), "")


if __name__ == "__main__":
    unittest.main()
