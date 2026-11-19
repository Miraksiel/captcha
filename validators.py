import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES, SUBMISSION_TYPES

# Базовая проверка доменного имени (RFC-совместимая, без схемы и пути)
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

MAGIC_SIGNATURES = {
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".pdf": (b"%PDF-",),
}


def parse_target_lines(raw_targets: str) -> list[str]:
    """Разбивает многострочный ввод на список непустых целей с обрезкой пробелов."""
    if not raw_targets:
        return []
    lines = [line.strip() for line in raw_targets.splitlines()]
    return [line for line in lines if line]


def validate_submission_type(submission_type: str) -> str:
    cleaned = (submission_type or "").strip()
    if cleaned not in SUBMISSION_TYPES:
        raise ValueError(f"Недопустимый Submission Type: {cleaned}. Ожидается Domain, IP или URL.")
    return cleaned


def validate_single_target(target: str, submission_type: str) -> str | None:
    """
    Проверяет одну строку списка на соответствие выбранному типу.
    Возвращает текст ошибки (str) или None, если цель корректна.
    """
    value = target.strip()
    if not value:
        return "Пустая строка цели"

    if submission_type == "Domain":
        if "://" in value or "/" in value:
            return "Для типа Domain укажите только домен (например, example.com) без http:// и пути"
        if not DOMAIN_REGEX.match(value):
            return f"Некорректный формат домена: {value}"
        return None

    if submission_type == "IP":
        try:
            ipaddress.ip_address(value)
            return None
        except ValueError:
            return f"Некорректный IP-адрес: {value}"

    if submission_type == "URL":
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "Для типа URL укажите полный адрес со схемой http:// или https://"
        if "." not in parsed.hostname and parsed.hostname != "localhost":
            return f"Некорректный хост в URL: {value}"
        return None

    return f"Неизвестный тип отправки: {submission_type}"


def validate_attachment(filename: str, content: bytes) -> None:
    """Проверяет расширение, размер до 2 МБ и сигнатуру файла."""
    ext = Path(filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Недопустимый формат файла '{ext or 'без расширения'}'. Разрешены только JPG, JPEG, PNG и PDF."
        )

    size = len(content)
    if size == 0:
        raise ValueError("Загруженный файл пуст (0 байт).")

    if size > MAX_FILE_SIZE_BYTES:
        size_mb = size / (1024 * 1024)
        raise ValueError(f"Файл превышает лимит 2 МБ (текущий размер: {size_mb:.2f} МБ).")

    expected_prefixes = MAGIC_SIGNATURES.get(ext, ())
    if expected_prefixes and not any(content.startswith(prefix) for prefix in expected_prefixes):
        raise ValueError(f"Содержимое файла не соответствует формату {ext.upper()}.")
