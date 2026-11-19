import asyncio
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import BASE_DIR, DRY_RUN, PORT, TARGET_FORM_URL, UPLOAD_DIR
from store import BatchStore
from submitter import submit_single_target
from validators import (
    parse_target_lines,
    validate_attachment,
    validate_submission_type,
)

app = FastAPI(
    title="Automated Form Submitter",
    description="Веб-инструмент для пакетной построчной отправки формы с отслеживанием CF-кодов и повтором ошибок",
    version="1.0.0",
)

STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

store = BatchStore()
worker_semaphore = asyncio.Semaphore(1)


class RetryRequest(BaseModel):
    index: int | None = None
    target: str | None = None


async def process_batch_items(batch_id: str, indices: list[int] | None = None) -> None:
    """Последовательно обрабатывает строки пакета по одной за раз."""
    async with worker_semaphore:
        batch = await store.get_batch(batch_id)
        if not batch:
            return

        await store.set_batch_status(batch_id, "running")
        items = batch.get("items", [])
        target_indices = indices if indices is not None else [item["index"] for item in items if item["status"] == "pending"]

        for idx in target_indices:
            current_batch = await store.get_batch(batch_id)
            if not current_batch:
                break
            item = current_batch["items"][idx]
            target_value = item["target"]

            await store.update_item(
                batch_id,
                idx,
                status="processing",
                sent=False,
                increment_attempt=True,
            )

            result = await submit_single_target(
                submission_type=current_batch["submission_type"],
                target=target_value,
                threat_type=current_batch["threat_type"],
                reason=current_batch["reason"],
                attachment_path=current_batch.get("attachment_path"),
            )

            if result.sent:
                await store.update_item(
                    batch_id,
                    idx,
                    status="sent",
                    sent=True,
                    confirmation_code=result.confirmation_code,
                    error_reason=None,
                )
            else:
                await store.update_item(
                    batch_id,
                    idx,
                    status="error",
                    sent=False,
                    confirmation_code=None,
                    error_reason=result.error_reason or "Неизвестная ошибка при отправке",
                )

        await store.set_batch_status(batch_id, "completed")


@app.get("/", response_class=FileResponse)
async def index_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config")
async def get_runtime_config() -> dict[str, Any]:
    return {
        "target_form_url": TARGET_FORM_URL,
        "dry_run": DRY_RUN,
    }


@app.get("/api/batches")
async def list_batches() -> dict[str, Any]:
    batches = await store.list_batches(limit=25)
    return {"batches": batches}


@app.get("/api/batches/{batch_id}")
async def get_batch(batch_id: str) -> dict[str, Any]:
    batch = await store.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Пакет не найден")
    return batch


@app.post("/api/batches")
async def create_and_run_batch(
    submission_type: str = Form(...),
    targets: str = Form(...),
    threat_type: str = Form(...),
    reason: str = Form(...),
    file: UploadFile | None = File(default=None),
) -> dict[str, Any]:
    try:
        cleaned_type = validate_submission_type(submission_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target_list = parse_target_lines(targets)
    if not target_list:
        raise HTTPException(status_code=400, detail="Введите хотя бы одну цель (Domain, IP или URL).")

    cleaned_threat = (threat_type or "").strip()
    if not cleaned_threat:
        raise HTTPException(status_code=400, detail="Выберите или укажите Threat Type.")

    cleaned_reason = (reason or "").strip()
    if not cleaned_reason:
        raise HTTPException(status_code=400, detail="Заполните поле Reason.")

    saved_filename: str | None = None
    saved_filepath: str | None = None

    if file and file.filename:
        content = await file.read()
        try:
            validate_attachment(file.filename, content)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        ext = Path(file.filename).suffix.lower()
        safe_name = f"{uuid.uuid4().hex[:12]}{ext}"
        dest = UPLOAD_DIR / safe_name
        dest.write_bytes(content)
        saved_filename = file.filename
        saved_filepath = str(dest)

    batch = await store.create_batch(
        submission_type=cleaned_type,
        targets=target_list,
        threat_type=cleaned_threat,
        reason=cleaned_reason,
        attachment_name=saved_filename,
        attachment_path=saved_filepath,
    )

    asyncio.create_task(process_batch_items(batch["id"]))
    return batch


@app.post("/api/batches/{batch_id}/retry")
async def retry_failed_items(batch_id: str, payload: RetryRequest | None = None) -> dict[str, Any]:
    batch = await store.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Пакет не найден")

    if batch.get("status") == "running":
        raise HTTPException(status_code=409, detail="Пакет сейчас выполняется, дождитесь завершения текущих строк")

    only_index = payload.index if payload else None
    new_target = payload.target if payload else None

    indices = await store.reset_failed_items(
        batch_id,
        only_index=only_index,
        new_target_value=new_target,
    )
    if not indices:
        raise HTTPException(status_code=400, detail="Нет строк со статусом ошибки для повторной отправки")

    asyncio.create_task(process_batch_items(batch_id, indices=indices))
    updated = await store.get_batch(batch_id)
    return updated or batch


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=PORT, reload=False)
