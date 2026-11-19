import asyncio
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import TimeoutError as PlaywrightTimeoutError, async_playwright

from captcha_provider import (
    CaptchaNotConfiguredError,
    CaptchaSolvingError,
    handle_captcha_step,
)
from config import CAPTCHA_API_KEY, DRY_RUN, HEADLESS, TARGET_FORM_URL
from validators import validate_single_target

CONFIRMATION_CODE_REGEX = re.compile(r"\b(CF-[A-Z0-9]{6,16})\b", re.IGNORECASE)


@dataclass
class SubmissionResult:
    sent: bool
    confirmation_code: str | None = None
    error_reason: str | None = None


async def submit_single_target(
    *,
    submission_type: str,
    target: str,
    threat_type: str,
    reason: str,
    attachment_path: str | None = None,
    dry_run: bool | None = None,
) -> SubmissionResult:
    """
    Отправляет одну строку в целевую форму.
    Каждая цель проходит валидацию, заполнение полей, шаг капчи и сабмит.
    """
    validation_error = validate_single_target(target, submission_type)
    if validation_error:
        return SubmissionResult(sent=False, error_reason=validation_error)

    is_dry_run = DRY_RUN if dry_run is None else dry_run
    if is_dry_run:
        await asyncio.sleep(0.35)
        lowered = target.lower()
        if "fail" in lowered or "error" in lowered or "timeout" in lowered:
            return SubmissionResult(
                sent=False,
                error_reason="Тестовая ошибка отправки (строка содержит маркер ошибки в режиме DRY_RUN)",
            )
        digest = hashlib.sha256(f"{submission_type}:{target}:{threat_type}".encode("utf-8")).hexdigest()[:8].upper()
        return SubmissionResult(sent=True, confirmation_code=f"CF-{digest}")

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=HEADLESS)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                await page.goto(TARGET_FORM_URL, wait_until="domcontentloaded", timeout=30000)

                # 1. Выбор Submission Type (Domain / IP / URL)
                selects = page.locator("select")
                select_count = await selects.count()
                if select_count >= 1:
                    first_select = selects.nth(0)
                    try:
                        await first_select.select_option(label=submission_type, timeout=5000)
                    except Exception:
                        await first_select.select_option(value=submission_type, timeout=5000)

                # 2. Заполнение поля цели (Domain / IP / URL)
                target_input = page.locator(
                    "input[type='text'], input[type='url'], input:not([type='file']):not([type='checkbox']):not([type='hidden']):not([type='submit'])"
                ).first
                await target_input.fill(target, timeout=5000)

                # 3. Выбор Threat Type
                if select_count >= 2:
                    threat_select = selects.nth(1)
                    try:
                        await threat_select.select_option(label=threat_type, timeout=5000)
                    except Exception:
                        try:
                            await threat_select.select_option(value=threat_type, timeout=5000)
                        except Exception:
                            return SubmissionResult(
                                sent=False,
                                error_reason=f"В выпадающем списке Threat Type не найден вариант '{threat_type}'",
                            )

                # 4. Заполнение Reason
                reason_box = page.locator("textarea").first
                await reason_box.fill(reason, timeout=5000)

                # 5. Прикрепление файла (если передан)
                if attachment_path:
                    file_path = Path(attachment_path)
                    if not file_path.exists():
                        return SubmissionResult(
                            sent=False,
                            error_reason="Прикрепленный файл не найден на сервере",
                        )
                    file_input = page.locator("input[type='file']").first
                    await file_input.set_input_files(str(file_path), timeout=5000)

                # 6. Галочка согласия с условиями (I accept the terms and conditions)
                terms_checkbox = page.locator("input[type='checkbox']").first
                if await terms_checkbox.count() > 0 and not await terms_checkbox.is_checked():
                    await terms_checkbox.check(timeout=5000)

                # 7. Шаг обработки капчи (вынесен в captcha_provider.py)
                await handle_captcha_step(page, TARGET_FORM_URL, CAPTCHA_API_KEY)

                # 8. Нажатие кнопки Submit
                submit_btn = page.locator("button[type='submit'], input[type='submit'], button:has-text('Submit')").first
                await submit_btn.click(timeout=5000)

                # 9. Ожидание ответа страницы и поиск кода подтверждения CF-XXXXXXXX
                await page.wait_for_timeout(2000)
                body_text = await page.locator("body").inner_text()
                match = CONFIRMATION_CODE_REGEX.search(body_text)
                if match:
                    return SubmissionResult(
                        sent=True,
                        confirmation_code=match.group(1).upper(),
                    )

                # Если код CF-XXXXXXXX не найден, ищем текст ошибки на странице
                error_locator = page.locator(".error, .alert-danger, [role='alert'], .text-red-500, .invalid-feedback")
                if await error_locator.count() > 0:
                    err_text = (await error_locator.first.inner_text()).strip()
                    if err_text:
                        return SubmissionResult(sent=False, error_reason=f"Ошибка формы: {err_text}")

                return SubmissionResult(
                    sent=False,
                    error_reason="Форма отправлена, но код подтверждения CF-XXXXXXXX не обнаружен в ответе страницы",
                )

            finally:
                await context.close()
                await browser.close()

    except CaptchaNotConfiguredError as exc:
        return SubmissionResult(sent=False, error_reason=str(exc))
    except CaptchaSolvingError as exc:
        return SubmissionResult(sent=False, error_reason=str(exc))
    except PlaywrightTimeoutError:
        return SubmissionResult(
            sent=False,
            error_reason="Превышено время ожидания загрузки формы или ответа сервера (Timeout)",
        )
    except Exception as exc:
        return SubmissionResult(
            sent=False,
            error_reason=f"Ошибка при взаимодействии с формой: {exc}",
        )
