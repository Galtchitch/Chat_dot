"""Сборка набора доверенных сертификатов из системного хранилища.

Нужна там, где TLS инспектируется корпоративным прокси (Kaspersky, Zscaler,
Fortinet и т. п.): его корневой CA есть в хранилище Windows, но отсутствует в
наборе certifi, которым по умолчанию пользуется httpx/requests.
"""

from __future__ import annotations

import base64
import logging
import ssl
from pathlib import Path

log = logging.getLogger("netmon.certs")

DEFAULT_BUNDLE = Path("certs") / "ca-bundle.pem"

#: Значение telegram.ca_bundle, при котором набор собирается автоматически.
AUTO = "auto"


def der_to_pem(der: bytes) -> str:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"


def system_roots() -> list[bytes]:
    """DER-сертификаты корневых центров из системного хранилища (Windows)."""
    enum = getattr(ssl, "enum_certificates", None)
    if enum is None:  # Linux/macOS: отдельного API нет
        return []

    roots: list[bytes] = []
    try:
        entries = enum("ROOT")
    except Exception as exc:  # noqa: BLE001
        log.debug("Не удалось прочитать системное хранилище: %s", exc)
        return []

    for der, encoding, trust in entries:
        if encoding != "x509_asn" or trust is False:
            continue
        roots.append(der)
    return roots


def build_bundle(destination: str | Path = DEFAULT_BUNDLE) -> tuple[Path, int]:
    """Записать PEM-набор: публичные ЦС (certifi) + корневые ЦС системы.

    Возвращает путь к файлу и число добавленных системных сертификатов.
    """
    path = Path(destination)
    if str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)

    parts: list[str] = []
    try:
        import certifi

        parts.append(Path(certifi.where()).read_text(encoding="ascii"))
    except Exception as exc:  # noqa: BLE001 - certifi необязателен
        log.debug("certifi недоступен: %s", exc)

    seen: set[bytes] = set()
    added = 0
    for der in system_roots():
        if der in seen:
            continue
        seen.add(der)
        parts.append(der_to_pem(der))
        added += 1

    path.write_text("".join(parts), encoding="ascii")
    return path, added
