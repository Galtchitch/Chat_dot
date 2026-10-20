"""Проверки доступности узлов: ICMP (ping), TCP-порт, HTTP."""

from __future__ import annotations

import asyncio
import platform
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .models import Host

SYSTEM = platform.system().lower()
PING_BIN = shutil.which("ping") or "ping"

_LATENCY_RE = re.compile(
    r"(?:time|время)[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс|milliseconds)",
    re.IGNORECASE,
)

#: Признак настоящего ответа узла: в строке есть TTL. У сообщений «узел
#: недоступен» от маршрутизатора TTL нет.
_REPLY_RE = re.compile(r"\bttl[=:]\s*\d+", re.IGNORECASE)

#: Строки, которыми ping сообщает, что узел не ответил.
_UNREACHABLE_MARKERS = (
    "недоступен",
    "не найден",
    "не удалось достичь",
    "unreachable",
    "превышен интервал",
    "timed out",
    "timeout",
    "destination host",
)


@dataclass
class CheckResult:
    """Результат одной проверки."""

    ok: bool
    latency_ms: float | None = None
    detail: str = ""


def _decode(data: bytes) -> str:
    """Windows-версия ping печатает в OEM-кодировке, поэтому пробуем несколько."""
    for encoding in ("utf-8", "cp866", "cp1251"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _ping_command(host: str, timeout: float) -> list[str]:
    if SYSTEM == "windows":
        return [PING_BIN, "-n", "1", "-w", str(int(timeout * 1000)), host]
    if SYSTEM == "darwin":
        # В macOS ключ -W задаётся в миллисекундах.
        return [PING_BIN, "-c", "1", "-W", str(int(timeout * 1000)), host]
    # Linux (iputils): -W в секундах.
    return [PING_BIN, "-c", "1", "-W", str(max(1, int(round(timeout)))), host]


async def run_command(cmd: list[str], timeout: float) -> tuple[int, str] | None:
    """Выполнить команду и вернуть код возврата и объединённый вывод."""
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + 5)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return None
    return process.returncode or 0, _decode(output)


def _ping_ok(code: int, output: str) -> bool:
    """Успех — только ответ самого узла.

    Windows возвращает код 0 и на сообщение «Ответ от <маршрутизатор>:
    Заданный узел недоступен», поэтому одного кода возврата недостаточно.
    Настоящий ответ содержит TTL, а в IPv6-выводе — хотя бы время отклика.
    """
    if code != 0:
        return False
    lowered = output.lower()
    if any(marker in lowered for marker in _UNREACHABLE_MARKERS):
        return False
    return bool(_REPLY_RE.search(output) or _LATENCY_RE.search(output))


def _ping_detail(output: str, code: int) -> str:
    """Понятная причина отказа для сообщения и статуса."""
    for line in output.splitlines():
        text = line.strip()
        if text and any(marker in text.lower() for marker in _UNREACHABLE_MARKERS):
            return text[:180]
    lines = output.strip().splitlines()
    return (lines[-1].strip() if lines else f"код возврата {code}")[:180]


async def ping(host: str, timeout: float = 3.0) -> CheckResult:
    """Проверка доступности через системную утилиту ``ping``."""
    try:
        outcome = await run_command(_ping_command(host, timeout), timeout)
    except FileNotFoundError:
        return CheckResult(False, None, "утилита ping не найдена в системе")
    except OSError as exc:
        return CheckResult(False, None, str(exc)[:180])

    if outcome is None:
        return CheckResult(False, None, f"таймаут {timeout:g} с")
    code, output = outcome
    if not _ping_ok(code, output):
        return CheckResult(False, None, _ping_detail(output, code))

    match = _LATENCY_RE.search(output)
    latency = float(match.group(1).replace(",", ".")) if match else None
    return CheckResult(True, latency, "ответ получен")


async def tcp(host: str, port: int, timeout: float = 3.0) -> CheckResult:
    """Проверка, что TCP-порт принимает соединения."""
    started = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except asyncio.TimeoutError:
        return CheckResult(False, None, f"таймаут {timeout:g} с")
    except OSError as exc:
        return CheckResult(False, None, (exc.strerror or str(exc))[:180])

    latency = (time.perf_counter() - started) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - закрытие соединения не критично
        pass
    return CheckResult(True, round(latency, 1), f"порт {port} открыт")


def _http_sync(url: str, timeout: float) -> CheckResult:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": "netmon/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            latency = (time.perf_counter() - started) * 1000
            return CheckResult(response.status < 400, round(latency, 1), f"HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        latency = (time.perf_counter() - started) * 1000
        return CheckResult(exc.code < 400, round(latency, 1), f"HTTP {exc.code}")
    except Exception as exc:  # noqa: BLE001 - причин отказа много, важен текст
        return CheckResult(False, None, str(exc)[:180])


async def http(url: str, timeout: float = 5.0) -> CheckResult:
    """Проверка HTTP-сервиса (выполняется в отдельном потоке)."""
    return await asyncio.to_thread(_http_sync, url, timeout)


def _http_url(host: Host) -> str:
    address = host.address
    if not address.startswith(("http://", "https://")):
        address = f"http://{address}"
    if host.port:
        parts = urlsplit(address)
        if parts.port is None:
            address = urlunsplit(
                (parts.scheme, f"{parts.hostname}:{host.port}", parts.path, parts.query, parts.fragment)
            )
    return address


async def check(host: Host, default_timeout: float = 3.0) -> CheckResult:
    """Выполнить проверку узла согласно его типу."""
    timeout = host.timeout or default_timeout
    kind = (host.kind or "icmp").lower()

    if kind == "tcp":
        if not host.port:
            return CheckResult(False, None, "не задан TCP-порт")
        return await tcp(host.address, int(host.port), timeout)
    if kind == "http":
        return await http(_http_url(host), max(timeout, 5.0))
    return await ping(host.address, timeout)
