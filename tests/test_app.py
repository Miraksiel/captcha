import asyncio
import os
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

# Подключаем корень проекта и включаем DRY_RUN для автономных тестов очереди
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["DRY_RUN"] = "true"

import app as app_module  # noqa: E402
from captcha_provider import (  # noqa: E402
    CaptchaSolvingError,
    request_2captcha_solution,
)
from validators import (  # noqa: E402
    parse_target_lines,
    validate_attachment,
    validate_single_target,
)


def test_parse_target_lines_trims_and_skips_empty():
    raw = "  example.com \n\n  test.org\r\n   \n sub.domain.net "
    assert parse_target_lines(raw) == ["example.com", "test.org", "sub.domain.net"]


def test_validate_single_target_by_type():
    assert validate_single_target("example.com", "Domain") is None
    assert validate_single_target("https://example.com", "Domain") is not None

    assert validate_single_target("192.0.2.1", "IP") is None
    assert validate_single_target("999.999.1.1", "IP") is not None

    assert validate_single_target("https://example.com/path?a=1", "URL") is None
    assert validate_single_target("example.com/path", "URL") is not None


def test_validate_attachment_limits_and_types():
    valid_png = b"\x89PNG\r\n\x1a\n" + b"0" * 128
    validate_attachment("evidence.png", valid_png)

    with pytest.raises(ValueError, match="Разрешены только"):
        validate_attachment("script.exe", b"MZ1234")

    oversized_pdf = b"%PDF-1.4\n" + b"0" * (2 * 1024 * 1024 + 10)
    with pytest.raises(ValueError, match="превышает лимит 2 МБ"):
        validate_attachment("big.pdf", oversized_pdf)


def test_batch_lifecycle_and_retry(tmp_path: Path):
    app_module.store.storage_path = tmp_path / "batches_test.json"
    app_module.store._batches = {}
    app_module.DRY_RUN = True

    with TestClient(app_module.app) as client:
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"x" * 64
        res = client.post(
            "/api/batches",
            data={
                "submission_type": "Domain",
                "targets": "good-one.com\nfail-target.com\ngood-two.org",
                "threat_type": "Phishing",
                "reason": "Automated phishing report test",
            },
            files={"file": ("proof.png", png_bytes, "image/png")},
        )
        assert res.status_code == 200
        batch = res.json()
        batch_id = batch["id"]
        assert len(batch["items"]) == 3

        # Дожидаемся завершения фоновой очереди в тестовом цикле
        time.sleep(1.3)

        status_res = client.get(f"/api/batches/{batch_id}")
        assert status_res.status_code == 200
        completed = status_res.json()
        items = completed["items"]

        assert items[0]["status"] == "sent"
        assert items[0]["confirmation_code"].startswith("CF-")
        assert items[1]["status"] == "error"
        assert items[1]["error_reason"] is not None
        assert items[2]["status"] == "sent"
        assert items[2]["confirmation_code"].startswith("CF-")

        # Исправляем упавшую 2-ю строку и отправляем повторно только её
        retry_res = client.post(
            f"/api/batches/{batch_id}/retry",
            json={"index": 1, "target": "fixed-target.com"},
        )
        assert retry_res.status_code == 200

        time.sleep(0.6)

        final_res = client.get(f"/api/batches/{batch_id}").json()
        assert final_res["items"][1]["status"] == "sent"
        assert final_res["items"][1]["confirmation_code"].startswith("CF-")
        assert final_res["items"][1]["attempts"] == 2
        assert final_res["items"][0]["attempts"] == 1


def test_2captcha_solution_flow_success():
    async def _runner():
        call_count = 0

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if "in.php" in str(request.url):
                return httpx.Response(200, json={"status": 1, "request": "TASK_12345"})
            if "res.php" in str(request.url):
                if call_count == 2:
                    return httpx.Response(200, json={"status": 0, "request": "CAPCHA_NOT_READY"})
                return httpx.Response(200, json={"status": 1, "request": "TOKEN_REC_ABC123"})
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            token = await request_2captcha_solution(
                api_key="test_key",
                sitekey="6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-",
                page_url="https://example.com",
                poll_interval=0.01,
                client=client,
            )
            assert token == "TOKEN_REC_ABC123"

    asyncio.run(_runner())


def test_2captcha_error_handling():
    async def _runner():
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": 0, "request": "ERROR_ZERO_BALANCE"})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(CaptchaSolvingError, match="ERROR_ZERO_BALANCE"):
                await request_2captcha_solution(
                    api_key="test_key",
                    sitekey="6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-",
                    page_url="https://example.com",
                    client=client,
                )

    asyncio.run(_runner())
