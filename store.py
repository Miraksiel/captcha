import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import BATCHES_FILE


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class BatchStore:
    """Хранилище пакетов отправки и результатов по каждой строке (с сохранением на диск)."""

    def __init__(self, storage_path: Path = BATCHES_FILE) -> None:
        self.storage_path = storage_path
        self._lock = asyncio.Lock()
        self._batches: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._batches = raw
        except Exception:
            self._batches = {}

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.storage_path.with_suffix(".tmp")
        temp_path.write_text(
            json.dumps(self._batches, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(self.storage_path)

    async def create_batch(
        self,
        submission_type: str,
        targets: list[str],
        threat_type: str,
        reason: str,
        attachment_name: str | None = None,
        attachment_path: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            batch_id = uuid.uuid4().hex[:10]
            now = _utc_now()
            items = [
                {
                    "index": idx,
                    "target": target,
                    "status": "pending",
                    "sent": False,
                    "confirmation_code": None,
                    "error_reason": None,
                    "attempts": 0,
                    "updated_at": now,
                }
                for idx, target in enumerate(targets)
            ]
            batch = {
                "id": batch_id,
                "created_at": now,
                "updated_at": now,
                "submission_type": submission_type,
                "threat_type": threat_type,
                "reason": reason,
                "attachment_name": attachment_name,
                "attachment_path": attachment_path,
                "status": "queued",
                "items": items,
            }
            self._batches[batch_id] = batch
            self._save()
            return batch

    async def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        async with self._lock:
            batch = self._batches.get(batch_id)
            if not batch:
                return None
            return json.loads(json.dumps(batch))

    async def list_batches(self, limit: int = 20) -> list[dict[str, Any]]:
        async with self._lock:
            values = list(self._batches.values())
            values.sort(key=lambda b: b.get("created_at", ""), reverse=True)
            return json.loads(json.dumps(values[:limit]))

    async def set_batch_status(self, batch_id: str, status: str) -> None:
        async with self._lock:
            batch = self._batches.get(batch_id)
            if not batch:
                return
            batch["status"] = status
            batch["updated_at"] = _utc_now()
            self._save()

    async def update_item(
        self,
        batch_id: str,
        index: int,
        *,
        status: str,
        sent: bool,
        confirmation_code: str | None = None,
        error_reason: str | None = None,
        increment_attempt: bool = False,
    ) -> dict[str, Any] | None:
        async with self._lock:
            batch = self._batches.get(batch_id)
            if not batch or index < 0 or index >= len(batch["items"]):
                return None
            item = batch["items"][index]
            item["status"] = status
            item["sent"] = sent
            item["confirmation_code"] = confirmation_code
            item["error_reason"] = error_reason
            if increment_attempt:
                item["attempts"] = int(item.get("attempts", 0)) + 1
            item["updated_at"] = _utc_now()
            batch["updated_at"] = _utc_now()
            self._save()
            return json.loads(json.dumps(item))

    async def reset_failed_items(
        self,
        batch_id: str,
        only_index: int | None = None,
        new_target_value: str | None = None,
    ) -> list[int]:
        """Переводит неудачные строки обратно в pending для повторной отправки."""
        async with self._lock:
            batch = self._batches.get(batch_id)
            if not batch:
                return []

            indices_to_retry: list[int] = []
            now = _utc_now()

            for item in batch["items"]:
                idx = item["index"]
                if only_index is not None and idx != only_index:
                    continue
                if item["status"] == "error":
                    if only_index is not None and new_target_value and new_target_value.strip():
                        item["target"] = new_target_value.strip()
                    item["status"] = "pending"
                    item["sent"] = False
                    item["confirmation_code"] = None
                    item["error_reason"] = None
                    item["updated_at"] = now
                    indices_to_retry.append(idx)

            if indices_to_retry:
                batch["status"] = "queued"
                batch["updated_at"] = now
                self._save()

            return indices_to_retry
